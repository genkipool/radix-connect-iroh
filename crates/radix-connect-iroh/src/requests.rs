//! The dApp requests a link carries, followed across connections so that one a wallet
//! lost is delivered again.
//!
//! A wallet keeps the requests it received in memory: when its app is closed, or the
//! system ends it in the background, they are gone, though the connector saw each one
//! confirmed. Neither end can tell the other it is going away (a process that is ended
//! runs no more code), so the wallet tells what it still has when it comes back:
//!
//! - the wallet's session notes each request its host took, and forgets it once the host
//!   answers it (or the dApp cancels it). The notes live in the app's process, so they
//!   are lost exactly when the requests are;
//! - on every connection the wallet sends them as an *inventory* datagram, which a
//!   connector that predates it ignores;
//! - the connector's session notes each request it delivered, and on an inventory sends
//!   again those delivered on an earlier connection that the wallet no longer has. One
//!   delivered on this connection is left alone: the inventory may predate it. A wallet
//!   that kept them (it was only in the background) lists them, and nothing is sent twice.
//!
//! Requests are read from the messages themselves (`interactionId`, `items`, a response's
//! `discriminator`); everything else a link carries is ignored here.

use std::collections::{HashMap, HashSet, VecDeque};

/// First byte of an inventory datagram.
const INVENTORY: u8 = 0x49;
/// Second byte: set when every request the wallet holds is listed.
const COMPLETE: u8 = 0x01;
/// Digests one inventory datagram holds: well under a relay path's datagram size. A
/// wallet holding more says it is incomplete, and nothing is sent again.
const MAX_LISTED: usize = 100;
/// Requests each end keeps note of, newest kept: one never answered is dropped at last.
const MAX_TRACKED: usize = 200;

/// What a message is to this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tracked {
    /// A dApp request (`interactionId` and `items`).
    Request(String),
    /// The dApp cancelling the request it names.
    Cancel(String),
    /// The wallet's answer to a request (`discriminator` `success` or `failure`).
    Response(String),
}

/// What `message` is, when it is a dApp request, a cancel or an answer.
pub(crate) fn classify(message: &str) -> Option<Tracked> {
    let value: serde_json::Value = serde_json::from_str(message).ok()?;
    let id = value.get("interactionId")?.as_str()?.to_owned();
    // An answer has items too: its discriminator tells it apart.
    match value.get("discriminator").and_then(|d| d.as_str()) {
        Some("success" | "failure") => return Some(Tracked::Response(id)),
        Some(_) => return None,
        None => {}
    }
    let items = value.get("items").filter(|items| items.is_object())?;
    Some(
        if items.get("discriminator").and_then(|d| d.as_str()) == Some("cancelRequest") {
            Tracked::Cancel(id)
        } else {
            Tracked::Request(id)
        },
    )
}

/// A request's digest in an inventory: the first 8 bytes of its id's BLAKE3 hash.
pub(crate) fn digest(interaction_id: &str) -> [u8; 8] {
    let hash = blake3::hash(interaction_id.as_bytes());
    let mut digest = [0; 8];
    digest.copy_from_slice(&hash.as_bytes()[..8]);
    digest
}

/// The wallet's inventory datagram for the requests it holds.
pub(crate) fn inventory<'a>(held: impl ExactSizeIterator<Item = &'a String>) -> Vec<u8> {
    let complete = held.len() <= MAX_LISTED;
    let mut datagram = Vec::with_capacity(2 + 8 * held.len().min(MAX_LISTED));
    datagram.push(INVENTORY);
    datagram.push(if complete { COMPLETE } else { 0 });
    for id in held.take(MAX_LISTED) {
        datagram.extend_from_slice(&digest(id));
    }
    datagram
}

/// What an inventory datagram says, or `None` when it is not one.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Inventory {
    pub(crate) complete: bool,
    pub(crate) digests: HashSet<[u8; 8]>,
}

pub(crate) fn read_inventory(datagram: &[u8]) -> Option<Inventory> {
    let [INVENTORY, flags, listed @ ..] = datagram else {
        return None;
    };
    if listed.len() % 8 != 0 {
        return None;
    }
    Some(Inventory {
        complete: flags & COMPLETE != 0,
        digests: listed
            .chunks_exact(8)
            .filter_map(|chunk| chunk.try_into().ok())
            .collect(),
    })
}

/// Wallet: the requests its host took and has not answered.
#[derive(Debug, Default)]
pub(crate) struct Held {
    ids: VecDeque<String>,
}

impl Held {
    /// The host took `message`, from the connector.
    pub(crate) fn took(&mut self, message: &str) {
        match classify(message) {
            Some(Tracked::Request(id)) => {
                if !self.ids.contains(&id) {
                    self.ids.push_back(id);
                    if self.ids.len() > MAX_TRACKED {
                        self.ids.pop_front();
                    }
                }
            }
            Some(Tracked::Cancel(id)) => self.ids.retain(|held| *held != id),
            _ => {}
        }
    }

    /// The host sent `message`, and the connector confirmed it.
    pub(crate) fn sent(&mut self, message: &str) {
        if let Some(Tracked::Response(id)) = classify(message) {
            self.ids.retain(|held| *held != id);
        }
    }

    pub(crate) fn inventory(&self) -> Vec<u8> {
        inventory(self.ids.iter())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.ids.len()
    }
}

/// Connector: a request it delivered, to send again if the wallet loses it.
#[derive(Debug)]
struct Delivery {
    message: String,
    /// The number of the connection it was last delivered on.
    connection: u64,
}

/// Connector: the requests it delivered that the wallet has not answered.
#[derive(Debug, Default)]
pub(crate) struct Delivered {
    requests: HashMap<String, Delivery>,
    order: VecDeque<String>,
}

impl Delivered {
    /// Whether `message` is a request already delivered on `connection`: sending it again
    /// there would show it twice (the host and an inventory racing to send it).
    pub(crate) fn already_on(&self, message: &str, connection: u64) -> bool {
        matches!(
            classify(message),
            Some(Tracked::Request(id)) if self.requests.get(&id).is_some_and(|d| d.connection == connection)
        )
    }

    /// The wallet confirmed `message`, sent on `connection`.
    pub(crate) fn sent(&mut self, message: &str, connection: u64) {
        match classify(message) {
            Some(Tracked::Request(id)) => self.note(id, message.to_owned(), connection),
            Some(Tracked::Cancel(id)) => self.forget(&id),
            _ => {}
        }
    }

    /// The host took `message`, from the wallet.
    pub(crate) fn took(&mut self, message: &str) {
        if let Some(Tracked::Response(id)) = classify(message) {
            self.forget(&id);
        }
    }

    /// The requests to deliver again on `connection` after `inventory` arrived on it,
    /// claimed for it: delivered on an earlier connection and no longer in the wallet.
    /// Nothing when the inventory is incomplete.
    pub(crate) fn lost(&mut self, inventory: &Inventory, connection: u64) -> Vec<(String, String)> {
        if !inventory.complete {
            return Vec::new();
        }
        let mut lost = Vec::new();
        for (id, delivery) in &mut self.requests {
            if delivery.connection < connection && !inventory.digests.contains(&digest(id)) {
                delivery.connection = connection;
                lost.push((id.clone(), delivery.message.clone()));
            }
        }
        lost
    }

    fn note(&mut self, id: String, message: String, connection: u64) {
        if self
            .requests
            .insert(
                id.clone(),
                Delivery {
                    message,
                    connection,
                },
            )
            .is_none()
        {
            self.order.push_back(id);
            if self.order.len() > MAX_TRACKED
                && let Some(oldest) = self.order.pop_front()
            {
                self.requests.remove(&oldest);
            }
        }
    }

    /// The host cancelled request `id`: it is not delivered again.
    pub(crate) fn forget(&mut self, id: &str) {
        if self.requests.remove(id).is_some() {
            self.order.retain(|noted| noted != id);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.requests.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: &str) -> String {
        format!(
            r#"{{"interactionId":"{id}","items":{{"discriminator":"transaction"}},"metadata":{{}}}}"#
        )
    }
    fn cancel(id: &str) -> String {
        format!(
            r#"{{"interactionId":"{id}","items":{{"discriminator":"cancelRequest"}},"metadata":{{}}}}"#
        )
    }
    fn answer(id: &str) -> String {
        format!(r#"{{"discriminator":"success","interactionId":"{id}","items":{{}}}}"#)
    }

    #[test]
    fn classifies_requests_cancels_and_answers_and_ignores_the_rest() {
        assert_eq!(classify(&request("a")), Some(Tracked::Request("a".into())));
        assert_eq!(classify(&cancel("a")), Some(Tracked::Cancel("a".into())));
        assert_eq!(classify(&answer("a")), Some(Tracked::Response("a".into())));
        assert_eq!(
            classify(r#"{"discriminator":"failure","interactionId":"a","error":"rejectedByUser"}"#),
            Some(Tracked::Response("a".into()))
        );
        // A ledger message, an account list, and what is not JSON at all.
        assert_eq!(
            classify(r#"{"discriminator":"getDeviceInfo","interactionId":"l"}"#),
            None
        );
        assert_eq!(
            classify(r#"{"discriminator":"accountList","accounts":[]}"#),
            None
        );
        assert_eq!(classify("not json"), None);
    }

    #[test]
    fn an_inventory_reads_back_what_it_lists() {
        let held = ["a".to_owned(), "b".to_owned()];
        let read = read_inventory(&inventory(held.iter())).unwrap();
        assert!(read.complete);
        assert_eq!(read.digests, HashSet::from([digest("a"), digest("b")]));
        assert_eq!(
            read_inventory(&[0x50, 0]),
            None,
            "a presence datagram is not one"
        );
        assert_eq!(read_inventory(&[INVENTORY, COMPLETE, 1, 2, 3]), None);
    }

    #[test]
    fn too_many_to_list_make_an_incomplete_inventory() {
        let held: Vec<String> = (0..MAX_LISTED + 1).map(|n| n.to_string()).collect();
        let read = read_inventory(&inventory(held.iter())).unwrap();
        assert!(!read.complete);
        assert_eq!(read.digests.len(), MAX_LISTED);
    }

    #[test]
    fn the_wallet_holds_what_its_host_took_until_it_answers_or_the_dapp_cancels() {
        let mut held = Held::default();
        held.took(&request("a"));
        held.took(&request("b"));
        held.took(&request("a"));
        assert_eq!(held.len(), 2);

        held.sent(&answer("a"));
        held.took(&cancel("b"));
        assert_eq!(held.len(), 0);
    }

    #[test]
    fn the_connector_sends_again_only_what_the_wallet_lost_on_an_earlier_connection() {
        let mut delivered = Delivered::default();
        delivered.sent(&request("kept"), 1);
        delivered.sent(&request("lost"), 1);
        delivered.sent(&request("new"), 2);
        let inventory = read_inventory(&inventory(["kept".to_owned()].iter())).unwrap();

        let lost = delivered.lost(&inventory, 2);

        assert_eq!(lost, vec![("lost".to_owned(), request("lost"))]);
        // Claimed for connection 2: a second inventory there sends nothing more, and the
        // host sending it there too is told it is already delivered.
        assert!(delivered.lost(&inventory, 2).is_empty());
        assert!(delivered.already_on(&request("lost"), 2));
        assert!(!delivered.already_on(&request("lost"), 3));
    }

    #[test]
    fn an_incomplete_inventory_sends_nothing_again() {
        let mut delivered = Delivered::default();
        delivered.sent(&request("a"), 1);
        let incomplete = Inventory {
            complete: false,
            digests: HashSet::new(),
        };
        assert!(delivered.lost(&incomplete, 2).is_empty());
    }

    #[test]
    fn a_request_the_host_cancelled_is_not_sent_again() {
        let mut delivered = Delivered::default();
        delivered.sent(&request("cancelled"), 1);
        delivered.sent(&request("kept"), 1);

        delivered.forget("cancelled");

        let empty = read_inventory(&inventory(std::iter::empty::<&String>())).unwrap();
        assert_eq!(
            delivered.lost(&empty, 2),
            vec![("kept".to_owned(), request("kept"))]
        );
    }

    #[test]
    fn answered_or_cancelled_requests_are_forgotten() {
        let mut delivered = Delivered::default();
        delivered.sent(&request("a"), 1);
        delivered.sent(&request("b"), 1);
        delivered.took(&answer("a"));
        delivered.sent(&cancel("b"), 1);
        assert_eq!(delivered.len(), 0);
    }
}
