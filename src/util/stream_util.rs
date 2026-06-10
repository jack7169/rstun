use crate::BUFFER_POOL;
use crate::tcp::AsyncStream;
use anyhow::Result;
use log::{debug, info};
use quinn::{RecvStream, SendStream};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::error::Elapsed;

const BUFFER_SIZE: usize = 8192;

/// Timeout applied to the in-band destination-address handshake when the
/// per-stream idle timeout is disabled (stream_timeout_ms == 0). The
/// handshake must always be bounded — only the steady-state relay may
/// run without an idle timeout.
const HANDSHAKE_TIMEOUT_MS: u64 = 30000;

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    InternalError,
    InvalidIPAddress,
    InvalidIPFamily,
    TimeoutError,
}

impl Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalError => write!(f, "InternalError"),
            Self::InvalidIPAddress => write!(f, "InvalidIPAddress"),
            Self::InvalidIPFamily => write!(f, "InvalidIPFamily"),
            Self::TimeoutError => write!(f, "TimeoutError"),
        }
    }
}

/// How one relay direction came to an end.
enum PumpEnd {
    /// Clean end-of-stream (TCP read returned 0 / QUIC recv finished).
    Eof,
    /// Transfer error or idle timeout.
    Failed(TransferError),
}

impl Display for PumpEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => write!(f, "eof"),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

pub struct StreamUtil {}

impl StreamUtil {
    /// Relay bidirectionally between a TCP stream and a QUIC stream pair.
    ///
    /// A single supervising task drives BOTH directions:
    ///
    /// - EITHER direction ending — clean EOF, error, or idle timeout —
    ///   tears the whole relay down deterministically: the QUIC send
    ///   stream is reset (unless it already finished cleanly), the QUIC
    ///   recv stream is stopped, the TCP write half is shut down, and
    ///   all halves are dropped so the TCP socket fully closes. The
    ///   peer relay observes the reset/finish and tears down its end
    ///   the same way, so the tunneled TCP endpoints see a close and
    ///   can re-establish. (Half-close draining is deliberately NOT
    ///   supported: the cancelled opposite pump may have lost a
    ///   partially-written chunk, and continuing after a silent gap
    ///   would desync the tunneled protocol — see the teardown comment.)
    /// - `stream_timeout_ms == 0` disables the per-stream idle timeout
    ///   entirely (long-lived trunk streams stay up while idle).
    ///
    /// The previous design ran the two directions as independent tasks
    /// coordinated by oneshot channels: a direction that hit its idle
    /// timeout blocked forever waiting for the *other* direction to end
    /// while still holding its TCP half. On a busy-one-way stream the
    /// other direction never ended — the dead direction's kernel Recv-Q
    /// grew unbounded and the relay became a permanent half-duplex
    /// zombie with nothing logged above debug level.
    pub fn start_flowing<S: AsyncStream>(
        tag: &'static str,
        stream: S,
        quic_stream: (SendStream, RecvStream),
        stream_timeout_ms: u64,
    ) {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                log::error!("failed to obtain peer address:{e}");
                return;
            }
        };

        let (mut stream_read, mut stream_write) = tokio::io::split(stream);
        let (mut quic_send, mut quic_recv) = quic_stream;
        let index = quic_send.id().index();

        debug!("[{tag}] START {index:<3} →  {peer_addr:<20}");

        tokio::spawn(async move {
            let mut up_bytes = 0u64;
            let mut down_bytes = 0u64;

            let (first_dir, first_end) = tokio::select! {
                end = Self::pump_stream_to_quic(
                    &mut stream_read,
                    &mut quic_send,
                    &mut up_bytes,
                    stream_timeout_ms,
                ) => ("tcp_to_quic", end),
                end = Self::pump_quic_to_stream(
                    &mut quic_recv,
                    &mut stream_write,
                    &mut down_bytes,
                    stream_timeout_ms,
                ) => ("quic_to_tcp", end),
            };

            // Either direction ending — for ANY reason — tears the whole
            // relay down immediately. The cancelled (select!-loser) pump
            // must NOT be resumed: write_all is not cancellation-safe, so
            // the loser may have read bytes it never finished writing.
            // Resuming it would continue the stream AFTER a silent gap,
            // desyncing the tunneled protocol for the rest of the stream
            // — strictly worse than truncating at teardown, which
            // endpoints already handle as a connection close.
            //
            // Teardown is a no-op (ignored error) on already-closed
            // halves. Dropping all four halves at the end of this task
            // closes the underlying TCP socket.
            //
            // reset() is gated: when the TCP→QUIC pump ended at clean
            // TCP EOF it already called quic_send.finish(), and Quinn
            // keeps retransmitting finished-stream data after the handle
            // drops (drop only auto-resets UNfinished streams). An
            // unconditional reset here would transition DataSent →
            // ResetSent and abandon the unacked tail — destroying the
            // very bytes just relayed (very plausible on a high-RTT
            // lossy path). Only reset when the send side did NOT finish
            // cleanly.
            let clean_finish =
                first_dir == "tcp_to_quic" && matches!(first_end, PumpEnd::Eof);
            if !clean_finish {
                let _ = quic_send.reset(0u32.into());
            }
            let _ = quic_recv.stop(0u32.into());
            let _ = stream_write.shutdown().await;

            info!(
                "[{tag}] relay {index} ended, {first_dir} {first_end}, \
                 up:{up_bytes}B down:{down_bytes}B, peer:{peer_addr}"
            );
        });
    }

    /// Drive the TCP→QUIC direction until EOF, error, or idle timeout.
    async fn pump_stream_to_quic<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream_read: &mut ReadHalf<S>,
        quic_send: &mut SendStream,
        transfer_bytes: &mut u64,
        stream_timeout_ms: u64,
    ) -> PumpEnd {
        let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
        loop {
            match Self::stream_to_quic(
                stream_read,
                quic_send,
                &mut buffer,
                transfer_bytes,
                stream_timeout_ms,
            )
            .await
            {
                Ok(0) => return PumpEnd::Eof,
                Ok(_) => {}
                Err(e) => return PumpEnd::Failed(e),
            }
        }
    }

    /// Drive the QUIC→TCP direction until EOF, error, or idle timeout.
    async fn pump_quic_to_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        quic_recv: &mut RecvStream,
        stream_write: &mut WriteHalf<S>,
        transfer_bytes: &mut u64,
        stream_timeout_ms: u64,
    ) -> PumpEnd {
        let mut buffer = BUFFER_POOL.alloc_and_fill(BUFFER_SIZE);
        loop {
            match Self::quic_to_stream(
                quic_recv,
                stream_write,
                &mut buffer,
                transfer_bytes,
                stream_timeout_ms,
            )
            .await
            {
                Ok(0) => return PumpEnd::Eof,
                Ok(_) => {}
                Err(e) => return PumpEnd::Failed(e),
            }
        }
    }

    async fn stream_to_quic<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        stream_read: &mut ReadHalf<S>,
        quic_send: &mut SendStream,
        buffer: &mut [u8],
        transfer_bytes: &mut u64,
        stream_timeout_ms: u64,
    ) -> Result<usize, TransferError> {
        let len_read = if stream_timeout_ms == 0 {
            stream_read
                .read(buffer)
                .await
                .map_err(|_| TransferError::InternalError)?
        } else {
            tokio::time::timeout(
                Duration::from_millis(stream_timeout_ms),
                stream_read.read(buffer),
            )
            .await
            .map_err(|_: Elapsed| TransferError::TimeoutError)?
            .map_err(|_| TransferError::InternalError)?
        };
        if len_read > 0 {
            *transfer_bytes += len_read as u64;
            quic_send
                .write_all(&buffer[..len_read])
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(len_read)
        } else {
            quic_send
                .finish()
                .map_err(|_| TransferError::InternalError)?;
            Ok(0)
        }
    }

    async fn quic_to_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        quic_recv: &mut RecvStream,
        stream_write: &mut WriteHalf<S>,
        buffer: &mut [u8],
        transfer_bytes: &mut u64,
        stream_timeout_ms: u64,
    ) -> Result<usize, TransferError> {
        let result = if stream_timeout_ms == 0 {
            quic_recv
                .read(buffer)
                .await
                .map_err(|_| TransferError::InternalError)?
        } else {
            tokio::time::timeout(
                Duration::from_millis(stream_timeout_ms),
                quic_recv.read(buffer),
            )
            .await
            .map_err(|_: Elapsed| TransferError::TimeoutError)?
            .map_err(|_| TransferError::InternalError)?
        };
        if let Some(len_read) = result {
            *transfer_bytes += len_read as u64;
            stream_write
                .write_all(&buffer[..len_read])
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(len_read)
        } else {
            stream_write
                .shutdown()
                .await
                .map_err(|_| TransferError::InternalError)?;
            Ok(0)
        }
    }

    pub async fn write_socket_addr(
        quic_send: &mut SendStream,
        addr: &Option<SocketAddr>,
        mark_none: bool,
    ) -> Result<()> {
        match addr {
            Some(SocketAddr::V4(v4)) => {
                let mut buf = [0u8; 1 + 4 + 2];
                buf[0] = 4;
                buf[1..5].copy_from_slice(&v4.ip().octets());
                buf[5..7].copy_from_slice(&v4.port().to_be_bytes());
                quic_send.write_all(&buf[..7]).await?;
            }
            Some(SocketAddr::V6(v6)) => {
                let mut buf = [0u8; 1 + 16 + 2];
                buf[0] = 6;
                buf[1..17].copy_from_slice(&v6.ip().octets());
                buf[17..19].copy_from_slice(&v6.port().to_be_bytes());
                quic_send.write_all(&buf[..19]).await?;
            }
            None => {
                if mark_none {
                    quic_send.write_u8(0).await?;
                }
            }
        };
        Ok(())
    }

    pub async fn read_socket_addr(
        quic_recv: &mut RecvStream,
        stream_timeout_ms: u64,
    ) -> Result<SocketAddr, TransferError> {
        // The handshake is always bounded, even when the per-stream
        // idle timeout is disabled.
        let handshake_timeout_ms = if stream_timeout_ms == 0 {
            HANDSHAKE_TIMEOUT_MS
        } else {
            stream_timeout_ms
        };
        let mut buf = [0u8; 19];
        tokio::time::timeout(
            Duration::from_millis(handshake_timeout_ms),
            quic_recv.read_exact(&mut buf[..7]),
        )
        .await
        .map_err(|_: Elapsed| TransferError::TimeoutError)?
        .map_err(|_| TransferError::InternalError)?;

        match buf[0] {
            4 => {
                let ip = Ipv4Addr::from(
                    <[u8; 4]>::try_from(&buf[1..5]).map_err(|_| TransferError::InvalidIPAddress)?,
                );
                let port = u16::from_be_bytes(buf[5..7].try_into().unwrap());
                Ok(SocketAddr::new(ip.into(), port))
            }
            6 => {
                tokio::time::timeout(
                    Duration::from_millis(handshake_timeout_ms),
                    quic_recv.read_exact(&mut buf[7..]),
                )
                .await
                .map_err(|_: Elapsed| TransferError::TimeoutError)?
                .map_err(|_| TransferError::InternalError)?;

                let ip = Ipv6Addr::from(
                    <[u8; 16]>::try_from(&buf[1..17])
                        .map_err(|_| TransferError::InvalidIPAddress)?,
                );
                let port = u16::from_be_bytes(buf[17..19].try_into().unwrap());
                Ok(SocketAddr::new(ip.into(), port))
            }
            _ => {
                log::error!("invalid address family");
                Err(TransferError::InvalidIPFamily)
            }
        }
    }
}
