//! Independent TLS 1.3 peer coverage using OpenSSL's actual handshake and record layer.
//!
//! Run explicitly with OpenSSL 3.x available on PATH or selected by OPENSSL_BIN:
//! `cargo test --lib --locked openssl_interop -- --ignored --nocapture`.
//! Missing or incompatible executables fail these tests rather than skip them.
//! The generated REALITY certificate is deliberately not trust-validated here.
//! This exercises TLS interoperability, not REALITY authentication or Xray qualification.

use std::{
    io::{self, Read, Write},
    pin::Pin,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    thread::JoinHandle,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    net::{
        TcpListener,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{mpsc, oneshot},
    time::timeout,
};

use super::{
    CertificateIdentity, CipherSuite, MAX_PLAINTEXT_LEN, ServerHelloTemplate, TlsApplicationIo,
    TlsApplicationReader, TlsApplicationWriter, VectoredRead, build_server_flight,
    read_client_finished, read_tls_record,
};
use crate::protocol::reality::{AuthKey, ClientHello, X25519_GROUP};

const WINDOW: Duration = Duration::from_secs(10);
const SUITES: [(CipherSuite, &str); 3] = [
    (CipherSuite::Aes128GcmSha256, "TLS_AES_128_GCM_SHA256"),
    (CipherSuite::Aes256GcmSha384, "TLS_AES_256_GCM_SHA384"),
    (
        CipherSuite::ChaCha20Poly1305Sha256,
        "TLS_CHACHA20_POLY1305_SHA256",
    ),
];

type Reader = TlsApplicationReader<OwnedReadHalf>;
type Writer = TlsApplicationWriter<OwnedWriteHalf>;

struct OpenSslPeer {
    child: Child,
    input: ChildStdin,
    output: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    pending: Vec<u8>,
    diagnostics: Arc<Mutex<Vec<u8>>>,
    pumps: Vec<JoinHandle<()>>,
}

impl OpenSslPeer {
    fn start(address: std::net::SocketAddr, suite: &str) -> Self {
        let executable = std::env::var_os("OPENSSL_BIN").unwrap_or_else(|| "openssl".into());
        let version = Command::new(&executable)
            .arg("version")
            .output()
            .expect("OpenSSL is required: install OpenSSL 3.x or set OPENSSL_BIN");
        assert!(version.status.success(), "OpenSSL version command failed");
        let identity = String::from_utf8_lossy(&version.stdout);
        assert!(
            identity.starts_with("OpenSSL 3."),
            "OpenSSL 3.x is required, got {identity}"
        );
        eprintln!(
            "TLS KeyUpdate peer: {} ({identity})",
            executable.to_string_lossy()
        );
        let mut child = Command::new(executable)
            .args([
                "s_client",
                "-tls1_3",
                "-brief",
                "-no_ign_eof",
                "-groups",
                "X25519",
                "-ciphersuites",
                suite,
                "-servername",
                "localhost",
                "-connect",
                &address.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("OpenSSL s_client must start");
        let input = child.stdin.take().expect("peer stdin is piped");
        let mut stdout = child.stdout.take().expect("peer stdout is piped");
        let mut stderr = child.stderr.take().expect("peer stderr is piped");
        let (send, output) = mpsc::unbounded_channel();
        let output_pump = std::thread::spawn(move || {
            let mut buffer = [0_u8; 8192];
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(length) => {
                        if send.send(Ok(buffer[..length].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = send.send(Err(error));
                        break;
                    }
                }
            }
        });
        let diagnostics = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&diagnostics);
        let error_pump = std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(length) = stderr.read(&mut buffer) {
                if length == 0 {
                    break;
                }
                capture
                    .lock()
                    .expect("diagnostics lock")
                    .extend_from_slice(&buffer[..length]);
            }
        });
        Self {
            child,
            input,
            output,
            pending: Vec::new(),
            diagnostics,
            pumps: vec![output_pump, error_pump],
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        // Inputs are short and sent only after the preceding input was consumed.
        self.input
            .write_all(bytes)
            .expect("peer input must remain open");
        self.input.flush().expect("peer input must flush");
    }

    async fn expect_plaintext(&mut self, expected: &[u8]) {
        while self.pending.len() < expected.len() {
            let next = timeout(WINDOW, self.output.recv()).await;
            match next {
                Ok(Some(Ok(bytes))) => self.pending.extend_from_slice(&bytes),
                other => panic!(
                    "OpenSSL did not decrypt expected application bytes: {other:?}\n{}",
                    self.diagnostics()
                ),
            }
        }
        assert_eq!(
            &self.pending[..expected.len()],
            expected,
            "OpenSSL plaintext ordering"
        );
        self.pending.drain(..expected.len());
    }

    fn diagnostics(&self) -> String {
        String::from_utf8_lossy(&self.diagnostics.lock().expect("diagnostics lock")).into_owned()
    }

    async fn finish(&mut self, writer: &mut Writer) {
        writer
            .shutdown(WINDOW)
            .await
            .expect("server close_notify must write");
        timeout(WINDOW, async {
            loop {
                if let Some(status) = self.child.try_wait().expect("peer status") {
                    assert!(status.success(), "OpenSSL failed: {}", self.diagnostics());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("OpenSSL must exit after close_notify");
        while let Some(bytes) = self.output.recv().await {
            self.pending
                .extend_from_slice(&bytes.expect("peer stdout read"));
        }
        assert!(
            self.pending.is_empty(),
            "unexpected extra OpenSSL plaintext"
        );
    }
}

impl Drop for OpenSslPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for pump in self.pumps.drain(..) {
            let _ = pump.join();
        }
    }
}

async fn connect(suite: CipherSuite, name: &str, proactive: bool) -> (OpenSslPeer, Reader, Writer) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let peer = OpenSslPeer::start(listener.local_addr().expect("listener address"), name);
    let (mut socket, _) = timeout(WINDOW, listener.accept())
        .await
        .unwrap_or_else(|error| {
            panic!("OpenSSL connection failed: {error}\n{}", peer.diagnostics())
        })
        .expect("accept OpenSSL");
    let record = read_tls_record(&mut socket, WINDOW)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "OpenSSL ClientHello failed: {error:?}\n{}",
                peer.diagnostics()
            )
        });
    let client =
        ClientHello::parse_record(record.wire()).expect("real OpenSSL ClientHello must parse");
    let template = ServerHelloTemplate::parse(&server_hello(&client, suite), &client)
        .expect("fixture ServerHello must match the real client");
    let flight = build_server_flight(
        &client,
        &AuthKey::from_test_bytes([0x99; 32]),
        template,
        &CertificateIdentity::from_seed([0x42; 32]),
        None,
    )
    .expect("production TLS flight must build");
    socket
        .write_all(flight.wire())
        .await
        .expect("server handshake flight");
    let mut established = read_client_finished(&mut socket, flight, WINDOW)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "OpenSSL must validate our handshake: {error:?}\n{}",
                peer.diagnostics()
            )
        });
    assert_eq!(established.suite(), suite);
    if proactive {
        // Lower the usage ceiling, not the sequence, so OpenSSL's nonces stay aligned.
        established.server_records_mut().set_test_key_usage_limit(3);
    }
    let (reader, writer) = TlsApplicationIo::new(socket, established).into_owned_split();
    (peer, reader, writer)
}

fn server_hello(client: &ClientHello, suite: CipherSuite) -> Vec<u8> {
    let session = client
        .session_id()
        .expect("OpenSSL compatibility session ID");
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x33; 32]);
    body.push(u8::try_from(session.len()).expect("session ID length"));
    body.extend_from_slice(session);
    body.extend_from_slice(&suite.wire_value().to_be_bytes());
    body.push(0);
    // supported_versions = TLS 1.3, key_share = X25519. The production builder
    // replaces the placeholder key share with its freshly generated public key.
    body.extend_from_slice(&46_u16.to_be_bytes());
    body.extend_from_slice(&[0, 43, 0, 2, 3, 4, 0, 51, 0, 36]);
    body.extend_from_slice(&X25519_GROUP.to_be_bytes());
    body.extend_from_slice(&32_u16.to_be_bytes());
    body.extend_from_slice(&[0x55; 32]);
    let mut message = vec![2];
    message.extend_from_slice(
        &u32::try_from(body.len())
            .expect("ServerHello length")
            .to_be_bytes()[1..],
    );
    message.extend_from_slice(&body);
    message
}

async fn expect_client_plaintext(reader: &mut Reader, expected: &[u8]) {
    let mut actual = Vec::new();
    while actual.len() < expected.len() {
        let record = reader
            .read_application(WINDOW)
            .await
            .expect("OpenSSL application record must authenticate");
        actual.extend_from_slice(record.plaintext());
    }
    assert_eq!(
        actual, expected,
        "client plaintext across traffic generations"
    );
}

fn patterned(generation: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index % 251) as u8 ^ generation)
        .collect()
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires real OpenSSL 3.x executable, selected by OPENSSL_BIN or PATH"]
async fn openssl_requested_key_updates_decrypt_both_directions_across_generations() {
    for (suite, name) in SUITES {
        let (mut peer, mut reader, mut writer) = connect(suite, name, false).await;
        for generation in 0..4 {
            if generation != 0 {
                // Basic s_client commands require a separate stdin read. Wait
                // for the authenticated control record before sending plaintext.
                peer.send(b"K\n");
                assert!(
                    reader
                        .read_application(WINDOW)
                        .await
                        .expect("requested KeyUpdate")
                        .is_empty()
                );
            }
            let upstream = format!("client generation {generation}\n");
            peer.send(upstream.as_bytes());
            expect_client_plaintext(&mut reader, upstream.as_bytes()).await;
            let downstream = patterned(generation, 2 * MAX_PLAINTEXT_LEN + 37);
            let stats = writer
                .write_application(&downstream, WINDOW)
                .await
                .expect("requested response and application data");
            assert_eq!(stats.plaintext_bytes(), downstream.len() as u64);
            peer.expect_plaintext(&downstream).await;
        }
        peer.finish(&mut writer).await;
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires real OpenSSL 3.x executable, selected by OPENSSL_BIN or PATH"]
async fn openssl_proactive_key_updates_preserve_plaintext_across_generations() {
    for (suite, name) in SUITES {
        let (mut peer, mut reader, mut writer) = connect(suite, name, true).await;
        for generation in 0..4 {
            let downstream = patterned(generation, 5 * MAX_PLAINTEXT_LEN + 17);
            writer
                .write_application(&downstream, WINDOW)
                .await
                .expect("proactive rotations must write");
            peer.expect_plaintext(&downstream).await;
            let upstream = format!("proactive generation {generation} accepted\n");
            peer.send(upstream.as_bytes());
            expect_client_plaintext(&mut reader, upstream.as_bytes()).await;
        }
        peer.finish(&mut writer).await;
    }
}

struct BatchSource {
    bytes: Vec<u8>,
    position: usize,
    entered: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

impl BatchSource {
    fn fill(&mut self, output: &mut [u8]) -> usize {
        let length = output.len().min(self.bytes.len() - self.position);
        output[..length].copy_from_slice(&self.bytes[self.position..self.position + length]);
        self.position += length;
        length
    }
}

impl AsyncRead for BatchSource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let length = self.fill(output.initialize_unfilled());
        output.advance(length);
        Poll::Ready(Ok(()))
    }
}

impl VectoredRead for BatchSource {
    async fn read_vectored<'buf>(
        &'buf mut self,
        buffers: &'buf mut [io::IoSliceMut<'buf>],
    ) -> io::Result<usize> {
        if let Some(entered) = self.entered.take() {
            entered.send(()).expect("concurrent reader must be running");
        }
        if let Some(release) = self.release.take() {
            release
                .await
                .expect("reader must authenticate the update before releasing the batch");
        }
        Ok(buffers.iter_mut().map(|buffer| self.fill(buffer)).sum())
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires real OpenSSL 3.x executable, selected by OPENSSL_BIN or PATH"]
async fn openssl_concurrent_requested_update_and_proactive_batched_records_stay_ordered() {
    for (suite, name) in SUITES {
        let (mut peer, mut reader, mut writer) = connect(suite, name, true).await;
        // A full single-record read grows the production writer's batch storage.
        let warmup = patterned(7, MAX_PLAINTEXT_LEN);
        let mut source = BatchSource {
            bytes: warmup.clone(),
            position: 0,
            entered: None,
            release: None,
        };
        assert_eq!(
            writer
                .write_application_read_from_batched(&mut source, WINDOW)
                .await
                .expect("batch warmup"),
            warmup.len()
        );
        peer.expect_plaintext(&warmup).await;
        let batch = patterned(19, 4 * MAX_PLAINTEXT_LEN);
        let (entered_send, entered_receive) = oneshot::channel();
        let (release_send, release_receive) = oneshot::channel();
        let mut source = BatchSource {
            bytes: batch.clone(),
            position: 0,
            entered: Some(entered_send),
            release: Some(release_receive),
        };
        let write = writer.write_application_read_from_batched(&mut source, WINDOW);
        let read = async {
            entered_receive
                .await
                .expect("writer must wait on batched source");
            peer.send(b"K\n");
            assert!(
                reader
                    .read_application(WINDOW)
                    .await
                    .expect("concurrent requested KeyUpdate")
                    .is_empty()
            );
            release_send
                .send(())
                .expect("batched writer must remain alive");
            let upstream = b"client bytes concurrent with batched downlink\n";
            peer.send(upstream);
            expect_client_plaintext(&mut reader, upstream).await;
        };
        let (written, ()) = timeout(WINDOW, async { tokio::join!(write, read) })
            .await
            .expect("concurrent batch must complete");
        assert_eq!(
            written.expect("batched write across rotations"),
            batch.len()
        );
        peer.expect_plaintext(&batch).await;
        let tail = b"tail after the concurrent batch\n";
        writer
            .write_application(tail, WINDOW)
            .await
            .expect("tail write");
        peer.expect_plaintext(tail).await;
        peer.finish(&mut writer).await;
    }
}
