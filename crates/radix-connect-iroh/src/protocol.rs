//! Message exchange over an established connection.
//!
//! Every application message travels on its own bidirectional QUIC stream:
//!
//! 1. the sender opens a stream, writes a 4-byte big-endian length followed by the
//!    UTF-8 JSON message, and finishes its half;
//! 2. the receiver reads exactly that many bytes (up to the size limit), hands the
//!    message to the application and, once the application took it, answers with a
//!    single status byte, then finishes;
//! 3. the sender's `send` completes when that status byte arrives.
//!
//! QUIC already gives reliability, ordering within a stream, flow control and
//! encryption, so the 11-15 KB chunking and the hashes of the WebRTC transport are
//! not needed. The length prefix makes a truncated message detectable whatever the
//! reason, and a stream abandoned half way is reset rather than finished. The status
//! byte keeps the "received by the peer" confirmation the extension's request queues
//! rely on.

use std::time::Duration;

use iroh::endpoint::{
    Connection, ReadExactError, ReadToEndError, RecvStream, SendStream, VarInt, WriteError,
};
use n0_future::time;

use crate::SendError;

/// ALPN of version 1 of this protocol.
pub const ALPN: &[u8] = b"radix-connect/iroh/1";

/// Status byte: the message was received and taken by the application.
const STATUS_RECEIVED: u8 = 0x00;
/// Status byte: the message was refused (too large, malformed or not UTF-8).
const STATUS_REJECTED: u8 = 0x01;

/// Size of the big-endian length prefix of a message.
const LENGTH_PREFIX: usize = 4;

/// Application error codes used when closing a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseCode {
    /// The session was closed by its owner.
    Normal = 0,
    /// The remote endpoint is not the peer of this link.
    Unauthorized = 1,
    /// A newer connection from the same peer replaced this one.
    Replaced = 2,
}

impl From<CloseCode> for VarInt {
    fn from(code: CloseCode) -> Self {
        VarInt::from_u32(code as u32)
    }
}

/// Stream error code sent when an incoming message exceeds the size limit.
const STREAM_MESSAGE_TOO_LARGE: u32 = 1;
/// Stream error code of a stream abandoned before it was complete.
const STREAM_ABANDONED: u32 = 2;

/// A send stream that is reset, not finished, if it is dropped before [`finish`].
///
/// Dropping a QUIC send stream finishes it, which would let the peer take whatever
/// was written so far for a complete message: a `send` cancelled or timed out half way
/// must abort its stream instead.
///
/// [`finish`]: Self::finish
#[derive(Debug)]
struct GuardedSendStream(Option<SendStream>);

impl GuardedSendStream {
    fn stream(&mut self) -> Result<&mut SendStream, WriteError> {
        self.0.as_mut().ok_or(WriteError::ClosedStream)
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
        self.stream()?.write_all(bytes).await
    }

    /// Finishes the stream, disarming the guard, and returns it so the caller can wait
    /// for the peer to acknowledge the data.
    fn finish(mut self) -> Result<SendStream, WriteError> {
        let mut stream = self.0.take().ok_or(WriteError::ClosedStream)?;
        stream.finish().map_err(|_| WriteError::ClosedStream)?;
        Ok(stream)
    }
}

impl Drop for GuardedSendStream {
    fn drop(&mut self) {
        if let Some(mut stream) = self.0.take() {
            let _ = stream.reset(VarInt::from_u32(STREAM_ABANDONED));
        }
    }
}

/// Sends `message` on a new stream and waits for the peer's status byte.
///
/// Two separate bounds: `transfer_timeout` for getting the whole message to the peer
/// (open, write, and the peer acknowledging every byte), so that a large message on a
/// slow link is not cut short; then `ack_timeout` for the peer's host to take it.
pub(crate) async fn send_message(
    conn: &Connection,
    message: &str,
    max_message_size: usize,
    transfer_timeout: Duration,
    ack_timeout: Duration,
) -> Result<(), SendError> {
    let too_large = SendError::MessageTooLarge {
        size: message.len(),
        max: max_message_size,
    };
    if message.len() > max_message_size {
        return Err(too_large);
    }
    let length = u32::try_from(message.len()).map_err(|_| too_large)?;
    let transfer = async {
        let (send, recv) = conn.open_bi().await.map_err(lost)?;
        let mut send = GuardedSendStream(Some(send));
        send.write_all(&length.to_be_bytes())
            .await
            .map_err(write_failed)?;
        send.write_all(message.as_bytes())
            .await
            .map_err(write_failed)?;
        let send = send.finish().map_err(write_failed)?;
        // Resolves once the peer acknowledged every byte, or stopped the stream.
        match send.stopped().await {
            Ok(None) => Ok(recv),
            Ok(Some(code)) => Err(write_failed(WriteError::Stopped(code))),
            Err(error) => Err(lost(error)),
        }
    };
    let mut recv = time::timeout(transfer_timeout, transfer)
        .await
        .unwrap_or(Err(SendError::Timeout))?;
    // The answer is exactly one byte; anything longer is a protocol violation.
    let answer = async {
        let status = recv.read_to_end(1).await.map_err(|error| match error {
            ReadToEndError::TooLong => SendError::Rejected,
            ReadToEndError::Read(error) => lost(error),
        })?;
        match status.as_slice() {
            [STATUS_RECEIVED] => Ok(()),
            [STATUS_REJECTED] => Err(SendError::Rejected),
            // The receiver went away before answering.
            _ => Err(SendError::ConnectionLost("no confirmation".to_owned())),
        }
    };
    time::timeout(ack_timeout, answer)
        .await
        .unwrap_or(Err(SendError::Timeout))
}

/// Outcome of reading one incoming stream.
#[derive(Debug)]
pub(crate) enum Incoming {
    /// A complete message, to be confirmed with [`Answer::acknowledge`] once the
    /// application took it.
    Message(String, Answer),
    /// The stream was refused and the peer told so; nothing to deliver.
    Refused,
    /// The stream ended before the message was complete; nothing to deliver or answer.
    Incomplete,
}

/// Reads one message from a stream the peer opened.
///
/// Oversized, malformed or non-UTF-8 messages are answered with a rejection here and
/// reported as [`Incoming::Refused`].
pub(crate) async fn read_message(
    send: SendStream,
    recv: &mut RecvStream,
    max_message_size: usize,
) -> Result<Incoming, ReadToEndError> {
    let answer = GuardedSendStream(Some(send));
    let mut prefix = [0u8; LENGTH_PREFIX];
    match recv.read_exact(&mut prefix).await {
        Ok(()) => {}
        Err(ReadExactError::FinishedEarly(_)) => return Ok(Incoming::Incomplete),
        Err(ReadExactError::ReadError(error)) => return Err(error.into()),
    }
    let length = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
    if length > max_message_size {
        tracing::warn!(
            length,
            max_message_size,
            "refusing an incoming message over the size limit"
        );
        // Ask the peer to stop sending the rest, then tell it why.
        let _ = recv.stop(VarInt::from_u32(STREAM_MESSAGE_TOO_LARGE));
        reject(answer).await;
        return Ok(Incoming::Refused);
    }
    let bytes = match recv.read_to_end(length).await {
        Ok(bytes) if bytes.len() == length => bytes,
        Ok(_) => return Ok(Incoming::Incomplete),
        // More bytes than announced: the sender does not follow the protocol.
        Err(ReadToEndError::TooLong) => {
            tracing::warn!("refusing an incoming message longer than its announced length");
            let _ = recv.stop(VarInt::from_u32(STREAM_MESSAGE_TOO_LARGE));
            reject(answer).await;
            return Ok(Incoming::Refused);
        }
        Err(error) => return Err(error),
    };
    match String::from_utf8(bytes) {
        Ok(message) => Ok(Incoming::Message(message, Answer(answer))),
        Err(_) => {
            tracing::warn!("refusing an incoming message that is not UTF-8");
            reject(answer).await;
            Ok(Incoming::Refused)
        }
    }
}

async fn reject(mut stream: GuardedSendStream) {
    // If the peer is gone it will not wait for the answer either: nothing to do.
    if stream.write_all(&[STATUS_REJECTED]).await.is_ok() {
        let _ = stream.finish();
    }
}

/// The receiver's half of a message stream. Dropped unanswered, it resets the stream,
/// which the sender reports as a lost connection.
#[derive(Debug)]
pub(crate) struct Answer(GuardedSendStream);

impl Answer {
    /// Confirms to the peer that the application took its message, and waits (at most
    /// `flush_timeout`) for the peer to acknowledge the confirmation, so that closing
    /// right after does not discard it.
    pub(crate) async fn acknowledge(self, flush_timeout: Duration) {
        let Self(mut stream) = self;
        if stream.write_all(&[STATUS_RECEIVED]).await.is_err() {
            return;
        }
        if let Ok(stream) = stream.finish() {
            let _ = time::timeout(flush_timeout, stream.stopped()).await;
        }
    }

    /// Resolves when the peer stops waiting for the answer (it gave up, or the
    /// connection ended).
    pub(crate) async fn peer_gave_up(&self) {
        match self.0.0.as_ref() {
            Some(stream) => {
                let _ = stream.stopped().await;
            }
            None => std::future::pending().await,
        }
    }
}

fn write_failed(error: WriteError) -> SendError {
    match error {
        WriteError::Stopped(code) if code == VarInt::from_u32(STREAM_MESSAGE_TOO_LARGE) => {
            SendError::Rejected
        }
        other => lost(other),
    }
}

fn lost(error: impl std::fmt::Display) -> SendError {
    SendError::ConnectionLost(error.to_string())
}

#[cfg(test)]
mod tests {
    use iroh::endpoint::{ReadError, presets};
    use iroh::test_utils::run_relay_server;
    use iroh::tls::CaTlsConfig;
    use iroh::{Endpoint, EndpointAddr, RelayMode};

    use super::*;

    /// Two endpoints connected through a local relay: these tests are about the
    /// streams, not about reaching the peer. The relay guard must outlive the test.
    async fn connected() -> (impl Sized, Endpoint, Endpoint, Connection, Connection) {
        let (_map, relay_url, relay) = run_relay_server().await.unwrap();
        let endpoint = |alpns: Vec<Vec<u8>>| {
            Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::custom([relay_url.clone()]))
                .ca_tls_config(CaTlsConfig::insecure_skip_verify())
                .alpns(alpns)
                .bind()
        };
        let server = endpoint(vec![ALPN.to_vec()]).await.unwrap();
        let client = endpoint(Vec::new()).await.unwrap();
        let target = EndpointAddr::new(server.id()).with_relay_url(relay_url.clone());
        // The server's half of the handshake must run while the client connects.
        let (client_conn, server_conn) = tokio::join!(client.connect(target, ALPN), async {
            server.accept().await.unwrap().await
        });
        let server_conn = server_conn.unwrap();
        (relay, server, client, client_conn.unwrap(), server_conn)
    }

    async fn read_one(conn: &Connection) -> Result<Incoming, ReadToEndError> {
        let (send, mut recv) = conn.accept_bi().await.unwrap();
        read_message(send, &mut recv, 1024).await
    }

    #[tokio::test]
    async fn a_dropped_send_stream_is_reset_not_finished() {
        let (_relay, _server, _client, client_conn, server_conn) = connected().await;
        let (send, _recv) = client_conn.open_bi().await.unwrap();
        let mut send = GuardedSendStream(Some(send));
        send.write_all(&100u32.to_be_bytes()).await.unwrap();
        send.write_all(b"partial").await.unwrap();
        drop(send);
        let read = read_one(&server_conn).await;
        assert!(
            matches!(read, Err(ReadToEndError::Read(ReadError::Reset(code))) if code == VarInt::from_u32(STREAM_ABANDONED)),
            "{read:?}"
        );
    }

    #[tokio::test]
    async fn a_message_shorter_than_announced_is_not_delivered() {
        let (_relay, _server, _client, client_conn, server_conn) = connected().await;
        let (mut send, _recv) = client_conn.open_bi().await.unwrap();
        send.write_all(&100u32.to_be_bytes()).await.unwrap();
        send.write_all(b"partial").await.unwrap();
        send.finish().unwrap();
        assert!(matches!(
            read_one(&server_conn).await,
            Ok(Incoming::Incomplete)
        ));
    }

    #[tokio::test]
    async fn a_message_longer_than_announced_is_refused() {
        let (_relay, _server, _client, client_conn, server_conn) = connected().await;
        let (mut send, mut recv) = client_conn.open_bi().await.unwrap();
        send.write_all(&2u32.to_be_bytes()).await.unwrap();
        send.write_all(b"{}{}").await.unwrap();
        send.finish().unwrap();
        assert!(matches!(
            read_one(&server_conn).await,
            Ok(Incoming::Refused)
        ));
        assert_eq!(recv.read_to_end(1).await.unwrap(), [STATUS_REJECTED]);
    }

    #[tokio::test]
    async fn a_complete_message_is_delivered_and_confirmed() {
        let (_relay, _server, _client, client_conn, server_conn) = connected().await;
        let (sent, read) = tokio::join!(
            send_message(
                &client_conn,
                "{\"ok\":true}",
                1024,
                Duration::from_secs(5),
                Duration::from_secs(5)
            ),
            async {
                match read_one(&server_conn).await {
                    Ok(Incoming::Message(message, answer)) => {
                        answer.acknowledge(Duration::from_secs(1)).await;
                        message
                    }
                    other => panic!("{other:?}"),
                }
            }
        );
        assert_eq!(sent, Ok(()));
        assert_eq!(read, "{\"ok\":true}");
    }
}
