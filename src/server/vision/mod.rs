//! Authenticated Vision session: request parse, route, outbound, and dual relays.
//!
//! [`VisionHandler`] sits after REALITY (or a resumed Handoff) has produced
//! application I/O. It reads the Vision request, compiles routing against the
//! inbound's UUID groups, selects an outbound, then runs uplink/downlink
//! (including XUDP and Handoff splice helpers) under request and I/O timeouts.
//! Nested-TLS padding decisions stay local to this module tree.

use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::protocol::reality::tls13::{TlsApplicationReader, TlsApplicationWriter};
use crate::protocol::vless::VERSION;
use crate::{
    accounting::{UsageLedger, UsageSession},
    logging::{LogEvent, Logger},
    protocol::handoff::IngressSource,
    protocol::vless::UserId,
};

use super::{
    direct::DirectHandoff,
    outbound::{OutboundConnectOutcome, OutboundRegistry, SessionOutboundOutcome},
    reality::RealityEstablished,
    routing::{AssetMatcher, RoutingCompileError, RoutingTable},
};
use crate::config::node::entry::EntryConfig;
use crate::config::node::routing::DomainStrategy;
use crate::io_activity::{SessionActivity, WRITE_STALL_TIMEOUT};
use crate::runtime::policy::EffectivePolicy;
use crate::runtime::policy::ResourceGovernorPolicy;
use crate::transport::TcpRelay;

pub(crate) mod bittorrent_monitor;
mod bittorrent_sniff;
mod nested;

use bittorrent_monitor::BitTorrentMonitor;

#[cfg(feature = "fuzzing")]
pub use nested::fuzz_nested_tls_header_prefix;
pub(crate) use nested::{NestedRead, NestedRecordReader, NestedTlsDetector, PaddingDecision};

mod abort;

mod request;

use request::{AcceptedVisionRequest, read_vision_request};

mod error;

pub use error::VisionSessionError;
use error::idle_failure;
#[cfg(test)]
use error::is_benign_teardown;

mod stats;

#[cfg(test)]
use stats::BoundaryBytes;
pub use stats::VisionRelayStats;
use stats::session_stats;

mod framing;

mod relay;
mod relay_downlink;
mod relay_uplink;

#[cfg(test)]
use framing::length_u64;
#[cfg(test)]
use relay::run_directional;
use relay::{SessionContext, join_directions};
use relay_downlink::relay_downlink;
use relay_uplink::relay_uplink;

mod handoff_relay;
mod handoff_resume;
mod xudp_session;

pub(crate) use handoff_resume::run_resumed_session;

/// The two owned TLS application halves of one authenticated Vision client.
pub(crate) struct VisionClientHalves {
    reader: TlsApplicationReader<OwnedReadHalf>,
    writer: TlsApplicationWriter<OwnedWriteHalf>,
}

impl VisionClientHalves {
    pub(crate) fn new(
        reader: TlsApplicationReader<OwnedReadHalf>,
        writer: TlsApplicationWriter<OwnedWriteHalf>,
    ) -> Self {
        Self { reader, writer }
    }
}

struct SourceAttribution {
    peer: Option<IpAddr>,
    proxy_source_verified: bool,
}

/// Immutable Vision data path with UUID-grouped routing and outbound selection.
#[derive(Clone)]
pub struct VisionHandler {
    outbounds: OutboundRegistry,
    routing: RoutingTable,
    relay: TcpRelay,
    request_timeout: Duration,
    io_timeout: Duration,
    dns_strategy: DomainStrategy,
    dns_timeout: Duration,
    usage: Option<UsageLedger>,
    user_labels: HashMap<UserId, String>,
    revoker: Option<crate::revocation::SessionRevoker>,
    access_log: Option<Logger>,
}

impl VisionHandler {
    /// Compiles validated config and one immutable asset snapshot.
    ///
    /// # Errors
    ///
    /// Returns a routing matcher or UUID compilation error.
    pub fn from_config(
        entry: &EntryConfig,
        policy: &EffectivePolicy,
        assets: Arc<dyn AssetMatcher>,
        relay: TcpRelay,
    ) -> Result<Self, RoutingCompileError> {
        Self::build(entry, policy, assets, relay, None)
    }

    /// Compiles the data path with a pressure-aware outbound registry.
    ///
    /// # Errors
    ///
    /// Returns a routing matcher or UUID compilation error.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per process-lifetime authority and generation input"
    )]
    pub(crate) fn from_config_with_pressure(
        entry: &EntryConfig,
        policy: &EffectivePolicy,
        assets: Arc<dyn AssetMatcher>,
        relay: TcpRelay,
        pressure: &crate::runtime::PressureGauge,
        direct_barrier: crate::runtime::DirectBarrier,
        governor: crate::runtime::ResourceGovernor,
        network_environment: crate::network::NetworkEnvironment,
        generation: u64,
        warm_authority: super::warm_pool::WarmPoolAuthority,
    ) -> Result<Self, RoutingCompileError> {
        Self::build(
            entry,
            policy,
            assets,
            relay,
            Some((
                pressure.clone(),
                direct_barrier,
                governor,
                network_environment,
                generation,
                warm_authority,
            )),
        )
    }

    fn build(
        entry: &EntryConfig,
        policy: &EffectivePolicy,
        assets: Arc<dyn AssetMatcher>,
        relay: TcpRelay,
        authorities: Option<(
            crate::runtime::PressureGauge,
            crate::runtime::DirectBarrier,
            crate::runtime::ResourceGovernor,
            crate::network::NetworkEnvironment,
            u64,
            super::warm_pool::WarmPoolAuthority,
        )>,
    ) -> Result<Self, RoutingCompileError> {
        let governor = &policy.governor;
        let connect_timeout = Duration::from_millis(governor.connect_timeout_ms);
        let declared = entry.outbounds.clone().unwrap_or_default();
        let network = entry.network.unwrap_or_default();
        let (outbounds, dns_governor) = match authorities {
            Some((
                _pressure,
                direct_barrier,
                dns_governor,
                network_environment,
                generation,
                warm_authority,
            )) => (
                OutboundRegistry::with_warm_pools(
                    &declared,
                    direct_barrier,
                    connect_timeout,
                    relay.fd_budget().clone(),
                    &network,
                    network_environment,
                    generation,
                    warm_authority,
                    &policy.warm_connections,
                ),
                dns_governor,
            ),
            None => (
                OutboundRegistry::with_barrier_and_network(
                    &declared,
                    crate::runtime::DirectBarrier::new(&policy.direct_barrier),
                    connect_timeout,
                    relay.fd_budget().clone(),
                    &network,
                    crate::network::NetworkEnvironment::detect(),
                ),
                crate::runtime::ResourceGovernor::new(governor),
            ),
        };
        Ok(Self::new_with_dns(
            outbounds,
            RoutingTable::compile(&entry.routing, &entry.users, assets, dns_governor)?,
            relay,
            governor,
            entry.routing.strategy(),
            Duration::from_millis(entry.dns.clone().unwrap_or_default().timeout_ms()),
        ))
    }

    /// Returns the shared outbound registry, for Handoff landings whose
    /// configured egress dials through the same compiled transports.
    #[must_use]
    pub const fn outbounds(&self) -> &OutboundRegistry {
        &self.outbounds
    }

    /// Enables process-lifetime user accounting for a panel-managed entry.
    /// Config validation has already checked every UUID and unique user ID.
    pub(crate) fn enable_usage(&mut self, usage: UsageLedger, entry: &EntryConfig, logger: Logger) {
        self.user_labels = entry
            .users
            .iter()
            .filter_map(|user| {
                let panel_user_id = user.panel_user_id.filter(|id| *id > 0)?;
                let uuid = uuid::Uuid::parse_str(&user.id).ok()?;
                Some((UserId::new(*uuid.as_bytes()), panel_user_id.to_string()))
            })
            .collect();
        self.usage = Some(usage);
        self.access_log = Some(logger);
    }

    pub(crate) fn enable_revocation(&mut self, revoker: crate::revocation::SessionRevoker) {
        self.revoker = Some(revoker);
    }

    fn record_access(
        &self,
        user_id: UserId,
        peer: Option<IpAddr>,
        destination: &crate::protocol::vless::Destination,
        network: &'static str,
        outbound: &str,
    ) {
        let Some((logger, source_ip, panel_user_id)) =
            self.access_log
                .as_ref()
                .zip(peer)
                .and_then(|(logger, peer)| {
                    self.user_labels
                        .get(&user_id)
                        .and_then(|label| label.parse::<u64>().ok())
                        .filter(|id| *id > 0)
                        .map(|id| (logger, peer, id))
                })
        else {
            return;
        };
        let address = match destination.address() {
            crate::protocol::vless::Address::Ipv4(ip) => ip.to_string(),
            crate::protocol::vless::Address::Ipv6(ip) => format!("[{ip}]"),
            crate::protocol::vless::Address::Domain(domain) => domain.clone(),
        };
        let _ = logger.emit(&LogEvent::AccessDecision {
            source_ip,
            network,
            destination: format!("{address}:{}", destination.port()),
            outbound: outbound.to_owned(),
            panel_user_id,
        });
    }

    /// Binds compiled routing and outbound snapshots to bounded session timeouts.
    #[must_use]
    pub fn new(
        outbounds: OutboundRegistry,
        routing: RoutingTable,
        relay: TcpRelay,
        governor: &ResourceGovernorPolicy,
    ) -> Self {
        Self::new_with_dns(
            outbounds,
            routing,
            relay,
            governor,
            DomainStrategy::AsIs,
            Duration::from_secs(5),
        )
    }

    /// Binds routing to an explicit bounded DNS strategy.
    #[must_use]
    pub fn new_with_dns(
        outbounds: OutboundRegistry,
        routing: RoutingTable,
        relay: TcpRelay,
        governor: &ResourceGovernorPolicy,
        dns_strategy: DomainStrategy,
        dns_timeout: Duration,
    ) -> Self {
        Self {
            outbounds,
            routing,
            relay,
            request_timeout: Duration::from_millis(governor.handshake_timeout_ms),
            io_timeout: WRITE_STALL_TIMEOUT,
            dns_strategy,
            dns_timeout,
            usage: None,
            user_labels: HashMap::new(),
            revoker: None,
            access_log: None,
        }
    }

    /// Reads, authorizes, connects, and relays one established REALITY session.
    ///
    /// The outbound descriptor permit is retained for the entire session; the
    /// direct-dial barrier permit ended when the dial resolved. Vision
    /// Direct unwraps outer TLS only after the authenticated command record has
    /// completed, and destination TLS is switched only on an exact record boundary.
    ///
    /// # Errors
    ///
    /// Returns bounded request, admission, destination, framing, TLS, or socket errors.
    pub async fn handle(
        &self,
        established: RealityEstablished,
    ) -> Result<VisionRelayStats, VisionSessionError> {
        self.handle_with_source(established, None, false).await
    }

    /// Handles one public session with its observed peer for panel accounting.
    /// `proxy_source_verified` is true only after the loopback PROXY v1 prelude
    /// has been successfully parsed by the public entry listener.
    pub(crate) async fn handle_with_source(
        &self,
        established: RealityEstablished,
        peer: Option<IpAddr>,
        proxy_source_verified: bool,
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let client_random = *established.client_random();
        let (application, inbound_tag, authenticated_users) = established.into_parts();
        let (mut client_reader, client_writer) = application.into_owned_split();
        let request = read_vision_request(
            &mut client_reader,
            &authenticated_users,
            self.request_timeout,
        )
        .await?;
        let user_id = match &request {
            AcceptedVisionRequest::Tcp { user_id, .. }
            | AcceptedVisionRequest::Xudp { user_id, .. } => *user_id,
        };
        let usage = self.usage.as_ref().and_then(|ledger| {
            ledger.start(
                user_id,
                self.user_labels.get(&user_id).map(String::as_str),
                peer,
            )
        });
        let mut lease = if let Some((revoker, label)) =
            self.revoker.as_ref().zip(self.user_labels.get(&user_id))
        {
            let panel_id = label
                .parse::<u64>()
                .map_err(|_| VisionSessionError::Revoked)?;
            Some(
                revoker
                    .register(user_id, panel_id)
                    .ok_or(VisionSessionError::Revoked)?,
            )
        } else {
            None
        };
        let session = async {
            if let AcceptedVisionRequest::Xudp {
                user_id,
                buffer,
                prefetched,
            } = request
            {
                return self
                    .handle_xudp(
                        client_reader,
                        client_writer,
                        inbound_tag.as_ref(),
                        user_id,
                        buffer,
                        prefetched,
                        usage,
                        peer,
                    )
                    .await;
            }
            self.handle_tcp_session(
                VisionClientHalves::new(client_reader, client_writer),
                inbound_tag.as_ref(),
                request,
                client_random,
                usage,
                SourceAttribution {
                    peer,
                    proxy_source_verified,
                },
            )
            .await
        };
        if let Some(lease) = &mut lease {
            tokio::select! {
                biased;
                () = lease.cancelled() => Err(VisionSessionError::Revoked),
                result = session => result,
            }
        } else {
            session.await
        }
    }

    /// Routes, dials, and relays one authenticated Vision TCP session.
    ///
    /// Handoff outbounds transfer before any client-visible response; Direct
    /// and NXR paths write the fixed VLESS response header and join the two
    /// relay directions under one session coordinator.
    async fn handle_tcp_session(
        &self,
        client: VisionClientHalves,
        inbound_tag: &str,
        request: AcceptedVisionRequest,
        client_random: [u8; 32],
        usage: Option<UsageSession>,
        source: SourceAttribution,
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let VisionClientHalves {
            reader: client_reader,
            writer: mut client_writer,
        } = client;
        let SourceAttribution {
            peer,
            proxy_source_verified,
        } = source;
        let AcceptedVisionRequest::Tcp {
            user_id,
            destination,
            buffer,
            prefetched,
        } = request
        else {
            unreachable!("Xudp branch returned above");
        };
        let route = self
            .routing
            .select_with_dns(
                user_id,
                inbound_tag,
                &destination,
                self.dns_strategy,
                self.dns_timeout,
            )
            .await
            .map_err(VisionSessionError::Route)?;
        let outcome = self
            .outbounds
            .connect_session_resolved(
                route.decision().outbound(),
                &destination,
                route.resolved_ips(),
            )
            .await
            .map_err(VisionSessionError::Outbound)?;
        self.record_access(
            user_id,
            peer,
            &destination,
            "tcp",
            route.decision().outbound(),
        );
        // The session-handoff boundary: routing has selected the outbound, no
        // client-visible response has been written, and no Vision encoder or
        // decoder exists yet. The downlink TLS sequence is zero normally or
        // one after a cover-shaped empty ApplicationData record. A handoff
        // outbound transfers that exact state to the landing node here.
        let outcome = match outcome {
            SessionOutboundOutcome::Handoff(line) => {
                return self
                    .relay_via_handoff(
                        &line,
                        VisionClientHalves::new(client_reader, client_writer),
                        AcceptedVisionRequest::Tcp {
                            user_id,
                            destination,
                            buffer,
                            prefetched,
                        },
                        client_random,
                        inbound_tag,
                        usage,
                        peer.map(|ip| {
                            if proxy_source_verified {
                                IngressSource::ProxyV1Verified(ip)
                            } else {
                                IngressSource::TcpPeerObserved(ip)
                            }
                        }),
                    )
                    .await;
            }
            SessionOutboundOutcome::Connected(outcome) => outcome,
        };
        let OutboundConnectOutcome::Connected(connection) = outcome else {
            client_writer
                .shutdown(self.io_timeout)
                .await
                .map_err(VisionSessionError::Tls)?;
            return Ok(VisionRelayStats::default());
        };
        let (destination_stream, outbound_permit) = connection.into_parts();
        let (destination_reader, destination_writer) = destination_stream.into_split();
        let protocol_monitor =
            self.access_log
                .as_ref()
                .zip(peer)
                .and_then(|(logger, source_ip)| {
                    let panel_user_id = self.user_labels.get(&user_id)?.parse::<u64>().ok()?;
                    (panel_user_id > 0).then(|| {
                        BitTorrentMonitor::new(
                            logger,
                            source_ip,
                            if proxy_source_verified {
                                "proxy_v1_verified"
                            } else {
                                "tcp_peer_observed"
                            },
                            panel_user_id,
                            inbound_tag,
                            &destination,
                        )
                    })
                });
        // The decoder accepted VLESS v0 and this inbound never negotiates
        // response Addons, so the response is a fixed stack value.
        let response_header = [VERSION, 0];

        // One coordinator per session. It holds two atomics, four socket-half
        // slots, and a version watch; never a queue and never a payload.
        let handoff = DirectHandoff::new();
        let activity = Arc::new(SessionActivity::with_usage(usage));
        let context = SessionContext {
            activity: &activity,
            timeout: self.io_timeout,
            handoff: &handoff,
            relay: &self.relay,
        };
        let uplink = relay_uplink(
            client_reader,
            destination_writer,
            user_id,
            buffer,
            prefetched,
            &context,
            protocol_monitor,
        );
        let downlink = relay_downlink(
            destination_reader,
            client_writer,
            user_id,
            &response_header,
            &context,
        );
        let (uplink, downlink) = join_directions(uplink, downlink, &activity).await?;
        drop(outbound_permit);
        Ok(session_stats(uplink, downlink))
    }
}

#[cfg(test)]
mod tests;
