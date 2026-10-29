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

    fn finish(mut self) -> Result<(), WriteError> {
        let mut stream = self.0.take().ok_or(WriteError::ClosedStream)?;
        stream.finish().map_err(|_| WriteError::ClosedStream)
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
pub(crate) async fn send_message(
    conn: &Connection,
    message: &str,
    max_message_size: usize,
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
    let exchange = async {
        let (send, mut recv) = conn.open_bi().await.map_err(lost)?;
        let mut send = GuardedSendStream(Some(send));
        send.write_all(&length.to_be_bytes())
            .await
            .map_err(write_failed)?;
        send.write_all(message.as_bytes())
            .await
            .map_err(write_failed)?;
        send.finish().map_err(write_failed)?;
        // The answer is exactly one byte; anything longer is a protocol violation.
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
    time::timeout(ack_timeout, exchange)
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
    /// Confirms to the peer that the application took its message.
    pub(crate) async fn acknowledge(self) {
        let Self(mut stream) = self;
        if stream.write_all(&[STATUS_RECEIVED]).await.is_ok() {
            let _ = stream.finish();
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
