use std::sync::Arc;
use std::time::Duration;

use iroh::RelayUrl;
use iroh::test_utils::run_relay_server;

use super::*;

/// Generous bound for anything that goes through the local relay.
const WAIT: Duration = Duration::from_secs(20);

fn config(relay_url: &RelayUrl) -> SessionConfig {
    let mut config = SessionConfig::new(relay_url.as_str()).unwrap();
    config.insecure_skip_relay_cert_verify = true;
    config.min_reconnect_delay = Duration::from_millis(50);
    config.max_reconnect_delay = Duration::from_millis(500);
    config
}

/// Reproduces the browser: no UDP, only the relay.
fn relay_only(relay_url: &RelayUrl) -> SessionConfig {
    let mut config = config(relay_url);
    config.relay_only = true;
    config
}

fn password(byte: u8) -> ConnectionPassword {
    ConnectionPassword::from_bytes([byte; 32])
}

async fn wait_for_state(session: &Session, wanted: ConnectionState) {
    time::timeout(WAIT, async {
        loop {
            match session.next_event().await {
                Some(SessionEvent::StateChanged(state)) if state == wanted => return,
                Some(_) => {}
                None => panic!("session closed while waiting for {wanted:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {wanted:?}"));
}

async fn next_message(session: &Session) -> String {
    time::timeout(WAIT, async {
        loop {
            match session.next_event().await {
                Some(SessionEvent::Message(message)) => return message,
                Some(SessionEvent::StateChanged(_)) => {}
                None => panic!("session closed while waiting for a message"),
            }
        }
    })
    .await
    .expect("timed out waiting for a message")
}

/// Sends `message` while the receiving host reads, as real hosts do: a message is only
/// confirmed once the receiving host takes it.
async fn deliver(sender: &Session, receiver: &Session, message: &str) -> Result<(), SendError> {
    let (sent, received) = tokio::join!(sender.send(message), next_message(receiver));
    assert_eq!(received, message);
    sent
}

async fn connected_pair(relay_url: &RelayUrl, link: &ConnectionPassword) -> (Session, Session) {
    let connector = Session::start(link, Role::Connector, relay_only(relay_url))
        .await
        .unwrap();
    let wallet = Session::start(link, Role::Wallet, config(relay_url))
        .await
        .unwrap();
    wait_for_state(&wallet, ConnectionState::Connected).await;
    wait_for_state(&connector, ConnectionState::Connected).await;
    (connector, wallet)
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_and_connector_exchange_messages_both_ways() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(1);
    let (connector, wallet) = connected_pair(&relay_url, &link).await;

    assert_eq!(wallet.peer_id(), connector.local_id());
    assert_eq!(connector.peer_id(), wallet.local_id());

    let request = r#"{"interactionId":"1","items":{"discriminator":"unauthorizedRequest"}}"#;
    deliver(&connector, &wallet, request).await.unwrap();

    let response = r#"{"interactionId":"1","discriminator":"success"}"#;
    deliver(&wallet, &connector, response).await.unwrap();

    wallet.close().await;
    connector.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn messages_keep_their_order() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(2)).await;

    // Concurrent sends are confirmed one by one, and read in the order they were sent.
    let sends = (0..20).map(|index| {
        let connector = &connector;
        async move {
            // Staggered so the streams are opened in index order.
            time::sleep(Duration::from_millis(index * 5)).await;
            connector.send(&format!("{{\"n\":{index}}}")).await
        }
    });
    let (sent, ()) = tokio::join!(n0_future::join_all(sends), async {
        for index in 0..20 {
            assert_eq!(next_message(&wallet).await, format!("{{\"n\":{index}}}"));
        }
    });
    assert!(sent.iter().all(Result::is_ok), "{sent:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn large_messages_arrive_intact() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(3)).await;

    // Larger than any WebRTC chunk, and multi-byte characters straddle every boundary.
    let message = "ñ€😀".repeat(200_000);
    deliver(&wallet, &connector, &message).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn send_without_a_peer_fails_immediately() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let wallet = Session::start(&password(4), Role::Wallet, config(&relay_url))
        .await
        .unwrap();
    let connector = Session::start(&password(5), Role::Connector, config(&relay_url))
        .await
        .unwrap();

    assert_eq!(wallet.send("{}").await, Err(SendError::NotConnected));
    assert_eq!(connector.send("{}").await, Err(SendError::NotConnected));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_cannot_connect() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(6);
    // Relay-only, as in the browser: every attempt arrives with a relay-attested id.
    let connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
        .await
        .unwrap();

    // A stranger who learned the connector's endpoint id, but not the password, dials
    // it with an endpoint key of its own.
    let stranger = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::custom([relay_url.clone()]))
        .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .unwrap();
    let target = EndpointAddr::new(connector.local_id()).with_relay_url(relay_url.clone());
    // Ignored before any handshake work: no answer at all, so no handshake completes.
    let attempt = time::timeout(Duration::from_secs(5), stranger.connect(target, ALPN)).await;
    assert!(
        !matches!(attempt, Ok(Ok(_))),
        "a stranger completed a handshake: {attempt:?}"
    );
    assert_eq!(connector.state(), ConnectionState::Disconnected);
    assert_eq!(connector.send("{}").await, Err(SendError::NotConnected));

    // Meanwhile the link's own wallet still gets in.
    let wallet = Session::start(&link, Role::Wallet, config(&relay_url))
        .await
        .unwrap();
    wait_for_state(&wallet, ConnectionState::Connected).await;
    stranger.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_reaching_the_connector_directly_is_rejected_after_the_handshake() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(14);
    // With UDP (native hosts), attempts can bypass the relay screening.
    let connector = Session::start(&link, Role::Connector, config(&relay_url))
        .await
        .unwrap();
    time::timeout(WAIT, connector.shared.endpoint.online())
        .await
        .unwrap();

    let stranger = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let direct = connector
        .shared
        .endpoint
        .bound_sockets()
        .into_iter()
        .filter(std::net::SocketAddr::is_ipv4)
        .map(|addr| std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, addr.port())));
    let target =
        EndpointAddr::new(connector.local_id()).with_addrs(direct.map(iroh::TransportAddr::Ip));
    let attempt = time::timeout(WAIT, stranger.connect(target, ALPN))
        .await
        .unwrap();
    if let Ok(connection) = attempt {
        // The client half of the handshake may finish before the connector's hook
        // closes the connection; it must then be closed as unauthorized.
        let reason = time::timeout(WAIT, connection.closed()).await.unwrap();
        assert!(
            matches!(
                &reason,
                iroh::endpoint::ConnectionError::ApplicationClosed(close)
                    if close.error_code == CloseCode::Unauthorized.into()
            ),
            "unexpected close reason: {reason:?}"
        );
    }
    assert_eq!(connector.state(), ConnectionState::Disconnected);
    stranger.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_send_never_delivers_a_partial_message() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(15)).await;

    // Abandon a large send at various points, repeatedly. One abandoned after the whole
    // message went out may still be delivered (that is what "timeout: may have been
    // delivered" means), but the connector's host, reading all along, must never see a
    // partial or empty message.
    let large = "x".repeat(4 * 1024 * 1024);
    for delay in [1, 5, 20, 50] {
        let cut = time::timeout(Duration::from_millis(delay), wallet.send(&large)).await;
        assert!(cut.is_err(), "the send finished within {delay} ms");
        let leaked = time::timeout(Duration::from_millis(300), next_message(&connector)).await;
        if let Ok(leaked) = leaked {
            assert_eq!(
                leaked.len(),
                large.len(),
                "a truncated message was delivered ({delay} ms)"
            );
        }
    }
    deliver(&wallet, &connector, "{\"after\":\"cancel\"}")
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_session_reports_disconnected() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (_connector, wallet) = connected_pair(&relay_url, &password(16)).await;
    assert_eq!(wallet.state(), ConnectionState::Connected);
    wallet.close().await;
    assert_eq!(wallet.state(), ConnectionState::Disconnected);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wallet_reconnects_when_the_connector_restarts() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(8);
    let (connector, wallet) = connected_pair(&relay_url, &link).await;

    connector.close().await;
    drop(connector);
    wait_for_state(&wallet, ConnectionState::Connecting).await;

    let connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
        .await
        .unwrap();
    wait_for_state(&connector, ConnectionState::Connected).await;
    wait_for_state(&wallet, ConnectionState::Connected).await;

    deliver(&connector, &wallet, "{\"after\":\"restart\"}")
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_wallet_connection_replaces_the_old_one() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(9);
    let (connector, first_wallet) = connected_pair(&relay_url, &link).await;

    // The app was killed without closing: its connection lingers until it times out.
    drop(first_wallet);
    let second_wallet = Session::start(&link, Role::Wallet, config(&relay_url))
        .await
        .unwrap();
    wait_for_state(&second_wallet, ConnectionState::Connected).await;

    // The connector may still hold the old connection for a moment.
    let (sent, received) = tokio::join!(
        time::timeout(WAIT, async {
            while connector.send("{\"to\":\"second\"}").await.is_err() {
                time::sleep(Duration::from_millis(50)).await;
            }
        }),
        next_message(&second_wallet)
    );
    sent.unwrap();
    assert_eq!(received, "{\"to\":\"second\"}");
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_messages_are_refused() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(10);
    let connector = Session::start(
        &link,
        Role::Connector,
        relay_only(&relay_url).with_max_message_size(1024),
    )
    .await
    .unwrap();
    let wallet = Session::start(&link, Role::Wallet, config(&relay_url))
        .await
        .unwrap();
    wait_for_state(&wallet, ConnectionState::Connected).await;
    wait_for_state(&connector, ConnectionState::Connected).await;

    // Refused locally, before anything is sent.
    assert_eq!(
        connector.send(&"x".repeat(2048)).await,
        Err(SendError::MessageTooLarge {
            size: 2048,
            max: 1024
        })
    );
    // Refused by the peer, which only accepts up to 1 KiB.
    assert_eq!(
        wallet.send(&"x".repeat(4096)).await,
        Err(SendError::Rejected)
    );
    // The link keeps working afterwards.
    deliver(&wallet, &connector, "{\"still\":\"alive\"}")
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_session_stops_cleanly() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(11)).await;

    wallet.close().await;
    wallet.close().await;
    assert_eq!(wallet.next_event().await, None);
    assert_eq!(wallet.send("{}").await, Err(SendError::Closed));
    wait_for_state(&connector, ConnectionState::Disconnected).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_the_host_does_not_take_is_not_confirmed() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(12);
    let connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
        .await
        .unwrap();
    let wallet_config = config(&relay_url).with_ack_timeout(Duration::from_millis(300));
    let wallet = Session::start(&link, Role::Wallet, wallet_config)
        .await
        .unwrap();
    wait_for_state(&wallet, ConnectionState::Connected).await;
    wait_for_state(&connector, ConnectionState::Connected).await;

    // The connector's host is not reading: nothing confirms the message.
    assert_eq!(
        wallet.send("{\"late\":true}").await,
        Err(SendError::Timeout)
    );

    // The wallet gave up on it, so it must not reach the host afterwards either: a
    // retry would otherwise deliver it twice.
    time::sleep(Duration::from_millis(500)).await;
    let late = time::timeout(Duration::from_millis(500), next_message(&connector)).await;
    assert!(late.is_err(), "a withdrawn message was delivered: {late:?}");

    // A message the host takes in time is confirmed, and the link keeps working.
    let (sent, received) = tokio::join!(wallet.send("{\"on\":\"time\"}"), next_message(&connector));
    assert_eq!(sent, Ok(()));
    assert_eq!(received, "{\"on\":\"time\"}");
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_withdraws_messages_the_host_has_not_taken() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(13);
    let connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
        .await
        .unwrap();
    let wallet = Session::start(&link, Role::Wallet, config(&relay_url))
        .await
        .unwrap();
    wait_for_state(&wallet, ConnectionState::Connected).await;
    wait_for_state(&connector, ConnectionState::Connected).await;

    // The connector closes while the wallet's message waits for its host: the wallet
    // must learn it was not delivered rather than get a confirmation.
    let (sent, ()) = tokio::join!(wallet.send("{}"), async {
        time::sleep(Duration::from_millis(300)).await;
        connector.close().await;
    });
    assert!(
        matches!(sent, Err(SendError::ConnectionLost(_) | SendError::Timeout)),
        "{sent:?}"
    );
    assert_eq!(connector.next_event().await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn diagnostics_describe_a_healthy_link() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(17)).await;
    // The relay-only connector talks to the wallet through the relay: that counts as
    // connected to it even before iroh reports its home relay.
    let early = connector.diagnostics();
    assert!(early.relay_connected, "{early}");
    time::timeout(WAIT, wallet.shared.endpoint.online())
        .await
        .unwrap();

    let snapshot = wallet.diagnostics();
    assert_eq!(snapshot.role, Role::Wallet);
    assert_eq!(snapshot.peer_id, connector.local_id());
    assert_eq!(snapshot.state, ConnectionState::Connected);
    assert!(snapshot.relay_connected, "{snapshot}");
    assert!(snapshot.path.is_some(), "{snapshot}");
    assert!(snapshot.connected_for.is_some(), "{snapshot}");
    assert_eq!(snapshot.failed_attempts, 0);
    assert_eq!(snapshot.last_error, None);
    // The connector reaches the wallet through the relay only, like a browser.
    assert_eq!(connector.diagnostics().path, Some(crate::PathKind::Relay));
}

#[tokio::test(flavor = "multi_thread")]
async fn diagnostics_explain_why_the_connection_ended() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(18)).await;

    connector.close().await;
    wait_for_state(&wallet, ConnectionState::Connecting).await;
    let snapshot = wallet.diagnostics();
    assert_eq!(snapshot.connected_for, None);
    assert_eq!(
        snapshot.last_error.as_deref(),
        Some("connection ended: the peer closed the session"),
        "{snapshot}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn diagnostics_count_failed_attempts() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let mut wallet_config = config(&relay_url);
    wallet_config.connect_timeout = Duration::from_millis(300);
    // Nobody listens for this link.
    let wallet = Session::start(&password(19), Role::Wallet, wallet_config)
        .await
        .unwrap();

    time::timeout(WAIT, async {
        while wallet.diagnostics().failed_attempts < 2 {
            time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let snapshot = wallet.diagnostics();
    assert_eq!(snapshot.state, ConnectionState::Connecting);
    assert!(
        snapshot
            .last_error
            .as_deref()
            .is_some_and(|error| error.starts_with("dial: ")),
        "{snapshot}"
    );
    assert!(
        snapshot.to_string().contains("failed_attempts="),
        "{snapshot}"
    );
}

/// [`Relays::Public`] against local stand-ins for n0's relays and address lookup.
fn public(relay_url: &RelayUrl, lookup: &Arc<iroh::test_utils::DnsPkarrServer>) -> SessionConfig {
    let mut config = SessionConfig::public();
    config.insecure_skip_relay_cert_verify = true;
    config.min_reconnect_delay = Duration::from_millis(50);
    config.max_reconnect_delay = Duration::from_millis(500);
    config.test_public_infrastructure = Some(crate::config::TestPublicInfrastructure {
        relay_url: relay_url.clone(),
        lookup: lookup.clone(),
    });
    config
}

#[tokio::test(flavor = "multi_thread")]
async fn with_public_relays_the_wallet_finds_the_connector_through_address_lookup() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let lookup = Arc::new(iroh::test_utils::DnsPkarrServer::run().await.unwrap());
    let link = password(20);

    let mut connector_config = public(&relay_url, &lookup);
    connector_config.relay_only = true;
    let connector = Session::start(&link, Role::Connector, connector_config)
        .await
        .unwrap();
    // The connector announces where it can be reached...
    lookup
        .on_endpoint(&connector.local_id(), WAIT)
        .await
        .unwrap();
    // ...and the wallet, configured with no relay URL at all, finds it.
    let wallet = Session::start(&link, Role::Wallet, public(&relay_url, &lookup))
        .await
        .unwrap();
    wait_for_state(&wallet, ConnectionState::Connected).await;
    wait_for_state(&connector, ConnectionState::Connected).await;
    deliver(&connector, &wallet, "{\"via\":\"public\"}")
        .await
        .unwrap();

    let snapshot = wallet.diagnostics();
    assert!(snapshot.public_relays, "{snapshot}");
    assert!(snapshot.to_string().contains(", public)"), "{snapshot}");
}

#[test]
fn admission_keeps_the_wallet_and_strangers_in_separate_bounded_pools() {
    let link = password(21);
    let wallet = link.endpoint_id(Role::Wallet);
    let stranger = password(22).endpoint_id(Role::Wallet);
    let relay = |endpoint_id| IncomingAddr::Relay {
        url: "https://relay.example.com".parse().unwrap(),
        endpoint_id,
    };
    let direct = IncomingAddr::Ip("192.0.2.7:4433".parse().unwrap());
    let idle = PendingHandshakes::default();
    let direct_full = PendingHandshakes {
        direct: MAX_DIRECT_HANDSHAKES,
        ..idle
    };
    let peer_full = PendingHandshakes {
        from_peer: MAX_PEER_HANDSHAKES,
        ..idle
    };
    let peer = Admission::Handshake { from_peer: true };

    // Direct attempts filling their pool never keep the link's wallet out.
    assert_eq!(admission(&relay(wallet), true, wallet, direct_full), peer);
    // But attempts in the wallet's name are bounded too: a relay attests the id, and
    // the relay is a third party.
    assert_eq!(
        admission(&relay(wallet), true, wallet, peer_full),
        Admission::Ignore
    );
    // Strangers via the relay never get handshake work.
    assert_eq!(
        admission(&relay(stranger), true, wallet, idle),
        Admission::Ignore
    );
    // Direct attempts prove their source address first, then share the bounded pool,
    // which the wallet's attempts do not use up.
    assert_eq!(
        admission(&direct, false, wallet, idle),
        Admission::ValidateAddress
    );
    assert_eq!(
        admission(&direct, true, wallet, peer_full),
        Admission::Handshake { from_peer: false }
    );
    assert_eq!(
        admission(&direct, true, wallet, direct_full),
        Admission::Ignore
    );
}

#[test]
fn pending_handshakes_are_counted_by_origin() {
    let mut pending = PendingHandshakes::default();
    pending.started(true);
    pending.started(false);
    pending.started(false);
    pending.finished(false);
    assert_eq!((pending.from_peer, pending.direct), (1, 1));
    pending.finished(true);
    pending.finished(true);
    assert_eq!((pending.from_peer, pending.direct), (0, 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_message_is_not_cut_short_by_the_confirmation_timeout() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(23);
    let connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
        .await
        .unwrap();
    // The confirmation timeout is far shorter than the transfer takes through the relay:
    // it must only start once every byte reached the peer.
    let wallet_config = config(&relay_url).with_ack_timeout(Duration::from_millis(20));
    let wallet = Session::start(&link, Role::Wallet, wallet_config)
        .await
        .unwrap();
    wait_for_state(&wallet, ConnectionState::Connected).await;
    wait_for_state(&connector, ConnectionState::Connected).await;

    let large = "x".repeat(6 * 1024 * 1024);
    deliver(&wallet, &connector, &large).await.unwrap();
}

#[test]
fn a_wallet_replaced_again_and_again_waits_longer_and_longer() {
    let mut config = config(&"https://relay.example.com".parse().unwrap());
    config.max_reconnect_delay = Duration::from_secs(15);
    assert_eq!(
        delay_after_connection(0, &config),
        config.min_reconnect_delay
    );
    assert_eq!(delay_after_connection(1, &config), Duration::from_secs(15));
    assert_eq!(delay_after_connection(2, &config), Duration::from_secs(30));
    assert_eq!(delay_after_connection(3, &config), Duration::from_secs(60));
    assert_eq!(delay_after_connection(9, &config), MAX_REPLACED_DELAY);
    assert_eq!(
        delay_after_connection(u32::MAX, &config),
        MAX_REPLACED_DELAY
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_waiting_wallet_redials_only_on_network_changes_made_while_it_waits() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(24);
    let connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
        .await
        .unwrap();
    // Long waits between attempts: only a network change can make the wallet dial soon.
    let mut wallet_config = config(&relay_url);
    wallet_config.min_reconnect_delay = Duration::from_secs(60);
    wallet_config.max_reconnect_delay = Duration::from_secs(60);
    let wallet = Session::start(&link, Role::Wallet, wallet_config)
        .await
        .unwrap();
    wait_for_state(&wallet, ConnectionState::Connected).await;
    wait_for_state(&connector, ConnectionState::Connected).await;
    // Android reports network changes often, also while connected; iroh carries the
    // connection across them, so they must not count once it ended.
    wallet.network_changed().await;
    connector.close().await;

    // The wallet says at once that it is no longer connected, though it waits to dial.
    wait_for_state(&wallet, ConnectionState::Connecting).await;
    let connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
        .await
        .unwrap();
    time::sleep(Duration::from_secs(2)).await;
    assert_eq!(connector.state(), ConnectionState::Disconnected);

    // A network change made while it waits is a reason to dial at once.
    wallet.network_changed().await;
    wait_for_state(&connector, ConnectionState::Connected).await;
    wait_for_state(&wallet, ConnectionState::Connected).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_right_after_taking_a_message_still_confirms_it() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(25)).await;

    // The sender must learn the message arrived, or it would retry and duplicate it.
    let (sent, ()) = tokio::join!(wallet.send("{\"last\":true}"), async {
        assert_eq!(next_message(&connector).await, "{\"last\":true}");
        connector.close().await;
    });
    sent.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_reads_late_gets_the_latest_state_not_a_backlog() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(26);
    // The wallet's host reads nothing while the connector restarts several times: the
    // wallet keeps reconnecting meanwhile.
    let wallet = Session::start(&link, Role::Wallet, config(&relay_url))
        .await
        .unwrap();
    for _ in 0..3 {
        let connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
            .await
            .unwrap();
        wait_for_state(&connector, ConnectionState::Connected).await;
        connector.close().await;
    }
    let connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
        .await
        .unwrap();
    wait_for_state(&connector, ConnectionState::Connected).await;
    time::timeout(WAIT, async {
        while wallet.state() != ConnectionState::Connected {
            time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the wallet did not reconnect");

    // Reading late, the host gets the current state, not the stale ones in between.
    assert_eq!(
        wallet.next_event().await,
        Some(SessionEvent::StateChanged(ConnectionState::Connected))
    );
    assert!(
        time::timeout(Duration::from_millis(300), wallet.next_event())
            .await
            .is_err()
    );
    deliver(&connector, &wallet, "{\"still\":\"working\"}")
        .await
        .unwrap();
}
