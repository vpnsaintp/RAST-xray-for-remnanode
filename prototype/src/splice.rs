use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};

use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::TcpStream;

const PIPE_LIMIT: usize = 64;
const CHUNK: usize = 64 * 1024;
static POOL: Mutex<Vec<Pipe>> = Mutex::new(Vec::new());
static OPEN: AtomicUsize = AtomicUsize::new(0);

fn pipe_budget(soft_fd_limit: usize) -> usize {
    // Each pipe uses two descriptors; reserve at least 64 and at least 75%
    // of the process limit for sockets, listeners, logs and other files.
    (soft_fd_limit / 8)
        .min(soft_fd_limit.saturating_sub(64) / 2)
        .min(4096)
}

fn max_open_pipes() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            pipe_budget(usize::try_from(limit.rlim_cur).unwrap_or(usize::MAX))
        } else {
            0
        }
    })
}

struct PipeSlot<'a>(&'a AtomicUsize);

impl<'a> PipeSlot<'a> {
    fn acquire(open: &'a AtomicUsize, limit: usize) -> io::Result<Self> {
        let mut count = open.load(Relaxed);
        loop {
            if count >= limit {
                return Err(ErrorKind::WouldBlock.into());
            }
            match open.compare_exchange_weak(count, count + 1, Relaxed, Relaxed) {
                Ok(_) => return Ok(Self(open)),
                Err(current) => count = current,
            }
        }
    }
}

impl Drop for PipeSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("NIGHTVPN_SPLICE").is_some_and(|value| value == "1"))
}

struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
    // Fields drop in declaration order: release the slot after both FDs close.
    _slot: PipeSlot<'static>,
}

struct Lease {
    pipe: Option<Pipe>,
    pending: usize,
}

impl Lease {
    fn acquire() -> io::Result<Self> {
        let reused = POOL.lock().unwrap().pop();
        let pipe = match reused {
            Some(pipe) => pipe,
            None => {
                let slot = PipeSlot::acquire(&OPEN, max_open_pipes())?;
                let mut fds = [0; 2];
                // pipe2 initializes two owned descriptors on success.
                if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }
                    == -1
                {
                    return Err(io::Error::last_os_error());
                }
                // Keep the default capacity when the kernel rejects the increase.
                unsafe { libc::fcntl(fds[1], libc::F_SETPIPE_SZ, CHUNK as libc::c_int) };
                unsafe {
                    Pipe {
                        read: OwnedFd::from_raw_fd(fds[0]),
                        write: OwnedFd::from_raw_fd(fds[1]),
                        _slot: slot,
                    }
                }
            }
        };
        Ok(Self {
            pipe: Some(pipe),
            pending: 0,
        })
    }

    fn pipe(&self) -> &Pipe {
        self.pipe.as_ref().expect("active splice pipe")
    }

    fn drain(&mut self) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0; self.pending];
        let fd = self.pipe().read.as_raw_fd();
        let mut offset = 0;
        while offset < bytes.len() {
            let buffer = &mut bytes[offset..];
            // The lease owns the descriptor and exclusively tracks buffered bytes.
            let size =
                retry(|| unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) })?;
            if size == 0 {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            offset += size;
            self.pending -= size;
        }
        Ok(bytes)
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Cancellation can leave payload in the pipe. Close that pipe to keep
        // data from different connections isolated.
        if self.pending == 0 {
            let mut pool = POOL.lock().unwrap();
            if pool.len() < PIPE_LIMIT.min(max_open_pipes() / 2) {
                pool.push(self.pipe.take().expect("active splice pipe"));
            }
        }
    }
}

fn retry(mut call: impl FnMut() -> isize) -> io::Result<usize> {
    loop {
        let result = call();
        if result >= 0 {
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn move_bytes(input: RawFd, output: RawFd, size: usize) -> io::Result<usize> {
    // Both descriptors are owned by the caller throughout this syscall.
    retry(|| unsafe {
        libc::splice(
            input,
            std::ptr::null_mut(),
            output,
            std::ptr::null_mut(),
            size,
            libc::SPLICE_F_NONBLOCK,
        )
    })
}

fn unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP | libc::EPERM)
    )
}

pub enum Transfer {
    Complete,
    Buffered(Vec<u8>),
}

pub async fn copy(
    input: &TcpStream,
    output: &TcpStream,
    mut written: impl FnMut(usize),
) -> io::Result<Transfer> {
    let mut lease = match Lease::acquire() {
        Ok(lease) => lease,
        Err(_) => return Ok(Transfer::Buffered(Vec::new())),
    };
    let pipe_in = lease.pipe().write.as_raw_fd();
    let pipe_out = lease.pipe().read.as_raw_fd();
    loop {
        let n = input
            .async_io(Interest::READABLE, || {
                move_bytes(input.as_raw_fd(), pipe_in, CHUNK)
            })
            .await;
        lease.pending = match n {
            Ok(0) => return Ok(Transfer::Complete),
            Ok(size) => size,
            Err(error) if unsupported(&error) => return Ok(Transfer::Buffered(Vec::new())),
            Err(error) => return Err(error),
        };
        while lease.pending != 0 {
            let n = output
                .async_io(Interest::WRITABLE, || {
                    move_bytes(pipe_out, output.as_raw_fd(), lease.pending)
                })
                .await;
            let size = match n {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(size) => size,
                Err(error) if unsupported(&error) => return Ok(Transfer::Buffered(lease.drain()?)),
                Err(error) => return Err(error),
            };
            lease.pending -= size;
            written(size);
        }
    }
}

pub fn clone_socket(socket: &TcpStream) -> io::Result<TcpStream> {
    use std::os::fd::AsFd;
    let fd = socket.as_fd().try_clone_to_owned()?;
    TcpStream::from_std(std::net::TcpStream::from(fd))
}

pub async fn copy_tcp(a: &mut TcpStream, b: &mut TcpStream) -> io::Result<()> {
    use tokio::net::tcp::{ReadHalf, WriteHalf};
    async fn relay(mut read: ReadHalf<'_>, mut write: WriteHalf<'_>) -> io::Result<()> {
        if let Transfer::Buffered(tail) = copy(read.as_ref(), write.as_ref(), |_| {}).await? {
            write.write_all(&tail).await?;
            tokio::io::copy(&mut read, &mut write).await?;
        }
        write.shutdown().await
    }
    let (a_read, a_write) = a.split();
    let (b_read, b_write) = b.split();
    tokio::try_join!(relay(a_read, b_write), relay(b_read, a_write))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn pipe_budget_reserves_descriptors_and_returns_slots() {
        assert_eq!(pipe_budget(64), 0);
        assert_eq!(pipe_budget(128), 16);
        let open = AtomicUsize::new(0);
        let a = PipeSlot::acquire(&open, 2).unwrap();
        let _b = PipeSlot::acquire(&open, 2).unwrap();
        assert_eq!(
            PipeSlot::acquire(&open, 2).err().unwrap().kind(),
            ErrorKind::WouldBlock
        );
        drop(a);
        assert!(PipeSlot::acquire(&open, 2).is_ok());
    }

    #[tokio::test]
    async fn copies_and_counts_all_bytes_in_one_direction() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (client, input) = tokio::try_join!(TcpStream::connect(address), listener.accept())?;
        let (output, origin) = tokio::try_join!(TcpStream::connect(address), listener.accept())?;
        let (mut client, (input, _), mut output, (mut origin, _)) = (client, input, output, origin);
        let payload: Vec<_> = (0..1_048_576).map(|index| (index % 251) as u8).collect();
        let send = async {
            client.write_all(&payload).await?;
            client.shutdown().await
        };
        let receive = async {
            let mut received = Vec::new();
            origin.read_to_end(&mut received).await?;
            assert_eq!(received, payload);
            Ok(())
        };
        let relay = async {
            let mut total = 0;
            let result = copy(&input, &output, |size| total += size).await?;
            assert!(matches!(result, Transfer::Complete));
            assert_eq!(total, payload.len());
            output.shutdown().await
        };
        tokio::try_join!(send, receive, relay)?;
        Ok(())
    }
}
