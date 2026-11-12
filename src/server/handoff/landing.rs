//! LANDING-side Handoff session resume handler.
//!
//! Internal to [`crate::server::handoff`]: opens a sealed transfer, reconstructs
//! TLS application halves, and runs the resumed Vision session. Behavior-
//! preserving modularization only — no wire, crypto, or trust changes.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::crypto::StaticX25519Key;
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{self, Instant},
};
use zeroize::Zeroizing;

use crate::{
    accounting::UsageLedger,
    config::{
        SecretString,
        node::landing::{HandoffLandingConfig, LandingAccountingUser},
    },
    logging::Logger,
    network::NetworkEnvironment,
    protocol::{
        handoff::{
            HEADER_LEN, HandoffError, HandoffLandingKeys, HandoffPsk, HandoffReplayCache,
            SessionKind, message_len_from_header, open_transfer,
        },
        reality::tls13::{EstablishedTls, ExportedTlsState, resume_application_halves},
        vless::UserId,
    },
    runtime::{PressureGauge, ResourceGovernor},
    transport::{relay::RelayStats, tcp_relay::TcpRelay},
};

use super::super::{
    connector::{DestinationConnectError, DestinationConnector},
    outbound::{OutboundConnectOutcome, OutboundRegistry},
    pre_auth::{PreAuthGeneration, begin_authentication},
    vision::{VisionClientHalves, run_resumed_session},
};
use super::error::{HandoffLandingConfigError, HandoffLandingError};
use crate::config::node::network::NetworkConfig;
use crate::runtime::policy::ResourceGovernorPolicy;

/// One Handoff landing connection: verify and decrypt one transfer, dial the
/// transferred destination — directly, or through the listener's configured
/// egress outbound — then resume the session's Vision relay.
///
/// Every failure before the session relay starts closes the connection with
/// zero response bytes; LINE observes the close as a transfer rejection.
#[derive(Clone)]

pub struct HandoffLandingHandler {
    pub(crate) keys: HandoffLandingKeys,
    pub(crate) replay: HandoffReplayCache,
    maximum_time_difference: u64,
    connector: DestinationConnector,
    egress: Option<LandingEgress>,
    pre_auth_idle_timeout: Duration,
    authentication_timeout: Duration,
    pub(crate) governor: ResourceGovernor,
    pressure: PressureGauge,
    generation: PreAuthGeneration,
    pub(crate) relay: TcpRelay,
    /// Idle bound handed to the resumed Vision relay, so a stalled peer cannot
    /// park a landing session on its descriptors and permits forever.
    io_timeout: Duration,
    /// Native UDP channel port override (absent: the listener's port).
    udp_port: Option<u16>,
    /// Fixed native UDP channel MTU (absent: path MTU discovery).
    udp_mtu: Option<u16>,
    accounting: Option<(UsageLedger, Arc<HashMap<UserId, String>>)>,
    revoker: Option<crate::revocation::SessionRevoker>,
    access_log: Option<Logger>,
}

/// A validated outbound the landing dials transferred destinations through.
#[derive(Clone)]
struct LandingEgress {
    registry: OutboundRegistry,
    tag: Arc<str>,
}

impl HandoffLandingHandler {
    /// Compiles one validated listener while retaining its process-lifetime
    /// replay history across immutable runtime generations.
    ///
    /// When the listener configures `settings.egress`, the landing dials
    /// transferred destinations through that tag of the shared outbound
    /// registry instead of dialing directly; validation has already excluded
    /// unknown tags and handoff-typed outbounds.
    ///
    /// # Errors
    ///
    /// Rejects malformed or incorrectly sized key material.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per immutable landing policy and process authority"
    )]
    pub(crate) fn from_landing_with_replay(
        settings: &HandoffLandingConfig,
        egress: Option<&str>,
        replay: HandoffReplayCache,
        relay: TcpRelay,
        io_timeout: Duration,
        outbounds: &OutboundRegistry,
        network: &NetworkConfig,
        network_environment: NetworkEnvironment,
        governor: ResourceGovernor,
        pressure: PressureGauge,
        generation: PreAuthGeneration,
    ) -> Result<Self, HandoffLandingConfigError> {
        let timing = settings.timing();
        let psk = decode_key(&settings.psk)?;
        let secret = decode_key(&settings.private_key)?;
        let previous_psks = settings
            .previous_psks()
            .iter()
            .map(|key| decode_key(key).map(HandoffPsk::new))
            .collect::<Result<Vec<_>, _>>()?;
        let previous_secrets = settings
            .previous_private_keys()
            .iter()
            .map(|key| decode_key(key).map(|bytes| StaticX25519Key::new(&bytes)))
            .collect::<Result<Vec<_>, _>>()?;
        let keys = HandoffLandingKeys::with_previous(
            HandoffPsk::new(psk),
            previous_psks,
            StaticX25519Key::new(&secret),
            previous_secrets,
        )
        .ok_or(HandoffLandingConfigError::Key)?;
        let mut handler = Self::new(
            keys,
            replay,
            timing.max_time_difference_seconds,
            Duration::from_millis(timing.connect_timeout_ms),
            Duration::from_millis(timing.authentication_timeout_ms),
            relay,
            io_timeout,
        );
        handler.pre_auth_idle_timeout = Duration::from_millis(timing.pre_auth_idle_timeout_ms);
        handler.udp_port = settings.udp_port;
        handler.udp_mtu = settings.udp_mtu;
        handler.governor = governor;
        handler.pressure = pressure;
        handler.generation = generation;
        handler.connector = DestinationConnector::with_environment(
            Duration::from_millis(timing.connect_timeout_ms),
            *network,
            network_environment,
        );
        Ok(match egress {
            Some(name) => handler.with_egress(outbounds.clone(), name),
            None => handler,
        })
    }

    /// Selects the validated outbound the landing dials transferred
    /// destinations through, replacing the default direct dial.
    #[must_use]
    pub fn with_egress(mut self, outbounds: OutboundRegistry, tag: &str) -> Self {
        self.egress = Some(LandingEgress {
            registry: outbounds,
            tag: Arc::from(tag),
        });
        self
    }

    /// Installs a panel mapping for post-Handoff plaintext accounting. When
    /// enabled, an unlisted UUID is refused before destination dialing.
    pub(crate) fn with_accounting(
        mut self,
        ledger: UsageLedger,
        users: &[LandingAccountingUser],
    ) -> Result<Self, HandoffLandingConfigError> {
        let mut labels = HashMap::with_capacity(users.len());
        for user in users {
            let uuid = uuid::Uuid::parse_str(&user.id)
                .map_err(|_| HandoffLandingConfigError::Accounting)?;
            if user.panel_user_id == 0
                || labels
                    .insert(
                        UserId::new(*uuid.as_bytes()),
                        user.panel_user_id.to_string(),
                    )
                    .is_some()
            {
                return Err(HandoffLandingConfigError::Accounting);
            }
        }
        self.accounting = Some((ledger, Arc::new(labels)));
        Ok(self)
    }

    pub(crate) fn with_access_log(mut self, logger: Logger) -> Self {
        self.access_log = Some(logger);
        self
    }

    pub(crate) fn with_revocation(mut self, revoker: crate::revocation::SessionRevoker) -> Self {
        self.revoker = Some(revoker);
        self
    }

    /// Creates a landing handler from already compiled policy.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per compiled listener policy input"
    )]
    pub fn new(
        keys: HandoffLandingKeys,
        replay: HandoffReplayCache,
        maximum_time_difference: u64,
        connect_timeout: Duration,
        authentication_timeout: Duration,
        relay: TcpRelay,
        io_timeout: Duration,
    ) -> Self {
        let governor = ResourceGovernor::new(&ResourceGovernorPolicy::default());
        Self {
            keys,
            replay,
            maximum_time_difference,
            connector: DestinationConnector::new(connect_timeout),
            egress: None,
            pre_auth_idle_timeout: Duration::from_secs(60),
            authentication_timeout,
            governor,
            pressure: PressureGauge::new(),
            generation: PreAuthGeneration::default(),
            relay,
            io_timeout,
            udp_port: None,
            udp_mtu: None,
            accounting: None,
            revoker: None,
            access_log: None,
        }
    }

    /// The native UDP channel port for a listener bound on `listener_port`.
    #[must_use]
    pub fn udp_port(&self, listener_port: u16) -> u16 {
        self.udp_port.unwrap_or(listener_port)
    }

    /// The policy the native UDP channel applies to new sessions of this
    /// generation: the same key material and clock window as TCP transfers.
    #[must_use]
    pub fn udp_policy(&self) -> super::udp::LandingUdpPolicy {
        super::udp::LandingUdpPolicy {
            keys: self.keys.clone(),
            maximum_time_difference: self.maximum_time_difference,
            fixed_mtu: self.udp_mtu,
            direct_egress: self.egress.is_none(),
        }
    }

    /// Processes a single Handoff TCP connection.
    ///
    /// Authentication failures return without writing a response and occur
    /// before destination DNS or connect. On success the transferred pending
    /// ciphertext is fed to the resumed record layer first, the prefetched
    /// payload enters a fresh Vision decoder first, and the first downlink is
    /// either an owed KeyUpdate response or the response header plus opening
    /// Vision frame. It is sealed at the exact transferred generation and
    /// sequence zero or one.
    ///
    /// # Errors
    ///
    /// Returns bounded transfer-read, clock, authentication, destination, or
    /// relay errors. Callers must silently close on every error.
    pub async fn handle(&self, mut inbound: TcpStream) -> Result<RelayStats, HandoffLandingError> {
        let authentication = begin_authentication(
            &mut inbound,
            self.pre_auth_idle_timeout,
            self.authentication_timeout,
            &self.governor,
            &self.pressure,
            &self.generation,
        )
        .await
        .map_err(HandoffLandingError::from_pre_auth)?;
        let message = read_transfer_after_first(
            &mut inbound,
            authentication.first_byte,
            authentication.deadline,
        )
        .await?;
        let now = unix_seconds()?;
        let opened = open_transfer(
            &message,
            &self.keys,
            &self.replay,
            now,
            self.maximum_time_difference,
        )
        .map_err(HandoffLandingError::Protocol)?;
        // The wire message's only consumer is `open_transfer`.
        drop(message);
        let state = opened.into_state();
        // Move both generation secrets into TLS state before touching the
        // network: a blob that cannot resume must not cost a destination
        // connection, and no duplicate secret representation survives.
        let (
            exported_tls,
            user_id,
            destination,
            pending,
            prefetched,
            key_update_response_pending,
            session_kind,
            _inbound_tag,
            policy,
            ingress_source,
        ) = state.into_parts().map_err(HandoffLandingError::Protocol)?;
        let tls = resume_tls(exported_tls)?;
        let user_id = UserId::new(user_id);
        let usage = if let Some((ledger, labels)) = &self.accounting {
            let label = labels
                .get(&user_id)
                .ok_or(HandoffLandingError::Protocol(HandoffError::State))?;
            ledger.start(user_id, Some(label), None)
        } else {
            None
        };
        let mut lease = if let Some(revoker) = &self.revoker {
            let panel_id = self
                .accounting
                .as_ref()
                .and_then(|(_, labels)| labels.get(&user_id))
                .and_then(|label| label.parse::<u64>().ok())
                .ok_or(HandoffLandingError::Protocol(HandoffError::State))?;
            Some(
                revoker
                    .register(user_id, panel_id)
                    .ok_or(HandoffLandingError::Protocol(HandoffError::State))?,
            )
        } else {
            None
        };
        // Authentication state no longer owns session material once the
        // continuation has been consumed into these move-only parts.
        drop(authentication);

        let session = async {
            if session_kind == SessionKind::Xudp {
                // XUDP never transfers TLS: LINE keeps the session and sends
                // authorized datagrams over the native UDP channel (ADR 0069). A
                // continuation claiming XUDP is refused like any invalid state,
                // with zero bytes and a silent close.
                return Err(HandoffLandingError::Protocol(HandoffError::State));
            }

            // TCP Vision resume (existing path).
            // The descriptor unit is reserved before connect(2) and outlives the
            // relay: the outbound socket closes before its unit is released. Both
            // permit slots are declared before the socket so either dial path
            // keeps that drop order. The egress registry and the default connector
            // each acquire and return their own correctly accounted unit.
            let _ = policy;
            let _fd_permit;
            let _egress_permit;
            let destination_stream = match &self.egress {
                Some(egress) => match egress.registry.connect(&egress.tag, &destination).await {
                    Ok(OutboundConnectOutcome::Connected(connection)) => {
                        let (stream, permit) = connection.into_parts();
                        _egress_permit = permit;
                        stream
                    }
                    // A blackhole egress discards the session by configuration:
                    // end it without dialing and without an error, leaving the
                    // silent close the line node reads as a rejection.
                    Ok(OutboundConnectOutcome::Blocked) => return Ok(RelayStats::new(0, 0)),
                    Err(source) => return Err(HandoffLandingError::Egress(source)),
                },
                None => {
                    let connected = self
                        .connector
                        .connect_resolved_accounted(&destination, &[], self.relay.fd_budget())
                        .await
                        .map_err(|error| match error {
                            DestinationConnectError::DescriptorBudget => {
                                HandoffLandingError::DescriptorBudget
                            }
                            error => HandoffLandingError::Destination(error),
                        })?;
                    let (stream, permit) = connected.into_parts();
                    _fd_permit = permit;
                    stream
                }
            };
            let (reader_half, writer_half) = inbound.into_split();
            let (client_reader, client_writer) = resume_application_halves(
                reader_half,
                pending,
                writer_half,
                tls,
                key_update_response_pending,
            );
            // Only LINE's observed source inside the authenticated transfer
            // may identify a client. The LANDING TCP peer is the bridge itself.
            let protocol_monitor = self
                .access_log
                .as_ref()
                .zip(self.accounting.as_ref())
                .zip(ingress_source)
                .and_then(|((logger, (_, labels)), source)| {
                    let panel_id = labels.get(&user_id)?.parse::<u64>().ok()?;
                    (panel_id > 0).then(|| {
                        super::super::vision::bittorrent_monitor::BitTorrentMonitor::new(
                            logger,
                            source.ip(),
                            source.attribution(),
                            panel_id,
                            &_inbound_tag,
                            &destination,
                        )
                    })
                });
            let stats = run_resumed_session(
                VisionClientHalves::new(client_reader, client_writer),
                destination_stream,
                user_id,
                usage,
                prefetched,
                &self.relay,
                self.io_timeout,
                protocol_monitor,
            )
            .await
            .map_err(HandoffLandingError::Session)?;
            Ok(RelayStats::new(
                stats.uplink_bytes(),
                stats.downlink_bytes(),
            ))
        };
        if let Some(lease) = &mut lease {
            tokio::select! {
                biased;
                () = lease.cancelled() => Err(HandoffLandingError::Protocol(HandoffError::State)),
                result = session => result,
            }
        } else {
            session.await
        }
    }
}

/// Decodes one validated base64 32-byte secret; validated configuration has
/// already excluded every failure this maps to `Key`.
fn decode_key(key: &SecretString) -> Result<[u8; 32], HandoffLandingConfigError> {
    let decoded = Zeroizing::new(
        BASE64_URL_SAFE_NO_PAD
            .decode(key.expose())
            .map_err(|_| HandoffLandingConfigError::Key)?,
    );
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| HandoffLandingConfigError::Key)
}

/// Rebuilds the session's TLS application state from a verified transfer.
pub(super) fn resume_tls(state: ExportedTlsState) -> Result<EstablishedTls, HandoffLandingError> {
    EstablishedTls::from_exported_state(state)
        .map_err(|_| HandoffLandingError::Protocol(HandoffError::State))
}

async fn read_transfer_after_first(
    stream: &mut TcpStream,
    first_byte: u8,
    deadline: Instant,
) -> Result<Vec<u8>, HandoffLandingError> {
    let mut header = [0_u8; HEADER_LEN];
    header[0] = first_byte;
    read_exact_before(stream, &mut header[1..], deadline).await?;
    let total = message_len_from_header(&header).map_err(HandoffLandingError::Protocol)?;
    let mut message = Vec::new();
    message
        .try_reserve_exact(total)
        .map_err(|_| HandoffLandingError::Allocation)?;
    message.extend_from_slice(&header);
    message.resize(total, 0);
    read_exact_before(stream, &mut message[HEADER_LEN..], deadline).await?;
    Ok(message)
}

async fn read_exact_before(
    stream: &mut TcpStream,
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), HandoffLandingError> {
    time::timeout_at(deadline, stream.read_exact(output))
        .await
        .map_err(|_| HandoffLandingError::Timeout)?
        .map(|_| ())
        .map_err(HandoffLandingError::Read)
}

pub(super) fn unix_seconds() -> Result<u64, HandoffLandingError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| HandoffLandingError::Clock)
}
