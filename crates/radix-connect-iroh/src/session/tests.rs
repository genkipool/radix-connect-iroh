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
async fn a_cancelled_send_is_never_delivered() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(15)).await;

    // Abandon a large send half way, repeatedly: the connector's host, reading all
    // along, must never see a partial (or empty) message.
    let large = "x".repeat(4 * 1024 * 1024);
    for delay in [1, 5, 20, 50] {
        let cut = time::timeout(Duration::from_millis(delay), wallet.send(&large)).await;
        assert!(cut.is_err(), "the send finished within {delay} ms");
        let leaked = time::timeout(Duration::from_millis(300), next_message(&connector)).await;
        assert!(
            leaked.is_err(),
            "a cancelled send was delivered ({delay} ms)"
        );
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
