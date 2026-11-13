use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use rustls::pki_types::ServerName;
use rustls::{
    ClientConfig, ClientSide, Connection, ServerConfig, ServerSide, SideData, Tcp, VecInput,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

const HEADER_SIZE: usize = 5;
const MAX_RECORD_SIZE: usize = HEADER_SIZE + 16_384 + 2_048;

pub struct TlsStream<Side: SideData = ServerSide> {
    socket: TcpStream,
    preface: std::io::Cursor<Vec<u8>>,
    conn: Box<Connection<Side, Tcp>>,
    input: VecInput,
    record: Vec<u8>,
    read_offset: usize,
    plaintext: Vec<u8>,
    outgoing: Vec<u8>,
    write_offset: usize,
    direct_read: Arc<AtomicBool>,
    splice_boundary: Option<Arc<AtomicBool>>,
    closing: bool,
}

pub struct SpliceReader {
    socket: TcpStream,
    at_boundary: Arc<AtomicBool>,
}

impl SpliceReader {
    pub fn into_socket(self) -> Option<TcpStream> {
        self.at_boundary
            .load(Ordering::Relaxed)
            .then_some(self.socket)
    }
}

impl TlsStream<ServerSide> {
    pub async fn accept(
        socket: TcpStream,
        config: Arc<ServerConfig>,
        preface: Vec<u8>,
    ) -> io::Result<Self> {
        Self::handshake(
            socket,
            preface,
            Connection::new(config).map_err(io::Error::other)?,
            Vec::new(),
        )
        .await
    }

    pub fn prepare_splice(&mut self) -> Option<SpliceReader> {
        let socket = crate::splice::clone_socket(&self.socket).ok()?;
        let at_boundary = Arc::new(AtomicBool::new(self.read_boundary()));
        self.splice_boundary = Some(Arc::clone(&at_boundary));
        Some(SpliceReader {
            socket,
            at_boundary,
        })
    }
}

impl TlsStream<ClientSide> {
    pub async fn connect(
        socket: TcpStream,
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
    ) -> io::Result<Self> {
        let mut hello = Vec::new();
        let conn = config
            .connect(name)
            .build(&mut hello)
            .map_err(io::Error::other)?;
        Self::handshake(socket, Vec::new(), conn, hello).await
    }
}

impl<Side: SideData + Unpin> TlsStream<Side> {
    async fn handshake(
        socket: TcpStream,
        preface: Vec<u8>,
        conn: Connection<Side, Tcp>,
        outgoing: Vec<u8>,
    ) -> io::Result<Self> {
        let mut stream = Self {
            socket,
            preface: std::io::Cursor::new(preface),
            conn: Box::new(conn),
            input: VecInput::default(),
            record: vec![0; HEADER_SIZE],
            read_offset: 0,
            plaintext: Vec::new(),
            outgoing,
            write_offset: 0,
            direct_read: Arc::new(AtomicBool::new(false)),
            splice_boundary: None,
            closing: false,
        };
        stream.flush().await?;
        while stream.conn.is_handshaking() {
            if !std::future::poll_fn(|cx| stream.poll_record(cx)).await? {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            stream.flush().await?;
        }
        Ok(stream)
    }

    pub fn direct_read_control(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.direct_read)
    }

    fn read_boundary(&self) -> bool {
        self.plaintext.is_empty()
            && self.read_offset == 0
            && self.preface.position() == self.preface.get_ref().len() as u64
    }

    // Read at most one outer TLS record. The next record may already be raw Vision data.
    fn poll_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        while self.read_offset < self.record.len() {
            let mut destination = ReadBuf::new(&mut self.record[self.read_offset..]);
            if self.preface.position() < self.preface.get_ref().len() as u64 {
                ready!(Pin::new(&mut self.preface).poll_read(cx, &mut destination))?;
            } else {
                ready!(Pin::new(&mut self.socket).poll_read(cx, &mut destination))?;
            }
            if destination.filled().is_empty() {
                if self.read_offset != 0 {
                    return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                }
                return Poll::Ready(Ok(false));
            }
            self.read_offset += destination.filled().len();
            if self.read_offset == HEADER_SIZE && self.record.len() == HEADER_SIZE {
                let size =
                    HEADER_SIZE + usize::from(u16::from_be_bytes([self.record[3], self.record[4]]));
                if size > MAX_RECORD_SIZE {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "oversized TLS record",
                    )));
                }
                self.record.resize(size, 0);
            }
        }
        let mut wire = self.record.as_slice();
        while !wire.is_empty() {
            if self.input.read(&mut wire)? == 0 {
                return Poll::Ready(Ok(false));
            }
        }
        self.record.truncate(HEADER_SIZE);
        self.read_offset = 0;
        self.conn
            .read_tls(&mut self.input, &mut self.outgoing)
            .handle_all(&mut self.plaintext)
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        Poll::Ready(Ok(true))
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.outgoing.len() {
            let size = ready!(
                Pin::new(&mut self.socket).poll_write(cx, &self.outgoing[self.write_offset..])
            )?;
            if size == 0 {
                return Poll::Ready(Err(ErrorKind::WriteZero.into()));
            }
            self.write_offset += size;
        }
        self.outgoing.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<Side: SideData + Unpin> AsyncRead for TlsStream<Side> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while self.plaintext.is_empty() {
            if self.direct_read.load(Ordering::Relaxed) {
                return Pin::new(&mut self.socket).poll_read(cx, dst);
            }
            ready!(self.poll_flush_pending(cx))?;
            if !ready!(self.poll_record(cx))? {
                return Poll::Ready(Ok(()));
            }
        }
        let size = dst.remaining().min(self.plaintext.len());
        dst.put_slice(&self.plaintext[..size]);
        self.plaintext.drain(..size);
        if let Some(at_boundary) = &self.splice_boundary {
            at_boundary.store(self.read_boundary(), Ordering::Relaxed);
        }
        Poll::Ready(Ok(()))
    }
}

impl<Side: SideData + Unpin> AsyncWrite for TlsStream<Side> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = &mut *self;
        ready!(stream.poll_flush_pending(cx))?;
        let size = src.len().min(16_384);
        stream
            .conn
            .write((&src[..size]).into(), &mut stream.outgoing)
            .map_err(io::Error::other)?;
        if let Poll::Ready(Err(error)) = stream.poll_flush_pending(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(size))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush_pending(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = &mut *self;
        if !stream.closing {
            stream
                .conn
                .send_close_notify(&mut stream.outgoing)
                .map_err(io::Error::other)?;
            stream.closing = true;
        }
        ready!(stream.poll_flush_pending(cx))?;
        Pin::new(&mut stream.socket).poll_shutdown(cx)
    }
}
