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
    connector.send(request).await.unwrap();
    assert_eq!(next_message(&wallet).await, request);

    let response = r#"{"interactionId":"1","discriminator":"success"}"#;
    wallet.send(response).await.unwrap();
    assert_eq!(next_message(&connector).await, response);

    wallet.close().await;
    connector.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn messages_keep_their_order() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(2)).await;

    for index in 0..20 {
        connector.send(&format!("{{\"n\":{index}}}")).await.unwrap();
    }
    for index in 0..20 {
        assert_eq!(next_message(&wallet).await, format!("{{\"n\":{index}}}"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn large_messages_arrive_intact() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let (connector, wallet) = connected_pair(&relay_url, &password(3)).await;

    // Larger than any WebRTC chunk, and multi-byte characters straddle every boundary.
    let message = "ñ€😀".repeat(200_000);
    wallet.send(&message).await.unwrap();
    assert_eq!(next_message(&connector).await, message);
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
async fn a_wallet_with_another_password_cannot_connect() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(6);
    let connector = Session::start(&link, Role::Connector, config(&relay_url))
        .await
        .unwrap();

    // A stranger who learned the connector's endpoint id, but not the password, dials
    // it directly with an endpoint key of its own.
    let stranger = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::custom([relay_url.clone()]))
        .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .unwrap();
    let target = EndpointAddr::new(connector.local_id()).with_relay_url(relay_url.clone());
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
    assert_eq!(connector.send("{}").await, Err(SendError::NotConnected));
    stranger.close().await;
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

    connector.send("{\"after\":\"restart\"}").await.unwrap();
    assert_eq!(next_message(&wallet).await, "{\"after\":\"restart\"}");
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

    time::timeout(WAIT, async {
        while connector.send("{\"to\":\"second\"}").await.is_err() {
            time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(next_message(&second_wallet).await, "{\"to\":\"second\"}");
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
    wallet.send("{\"still\":\"alive\"}").await.unwrap();
    assert_eq!(next_message(&connector).await, "{\"still\":\"alive\"}");
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
async fn an_unconfirmed_message_times_out() {
    let (_relay_map, relay_url, _relay) = run_relay_server().await.unwrap();
    let link = password(12);
    let _connector = Session::start(&link, Role::Connector, relay_only(&relay_url))
        .await
        .unwrap();
    let mut wallet_config = config(&relay_url).with_ack_timeout(Duration::from_millis(300));
    wallet_config.max_message_size = 64;
    let wallet = Session::start(&link, Role::Wallet, wallet_config)
        .await
        .unwrap();
    wait_for_state(&wallet, ConnectionState::Connected).await;

    // The connector's host never consumes its events: once its buffer is full it
    // stops acknowledging, and the wallet's next send times out.
    let mut results = Vec::new();
    for _ in 0..EVENT_BUFFER + 2 {
        let result = wallet.send("{}").await;
        let timed_out = result == Err(SendError::Timeout);
        results.push(result);
        if timed_out {
            break;
        }
    }
    let (last, earlier) = results.split_last().unwrap();
    assert_eq!(last, &Err(SendError::Timeout));
    assert!(earlier.iter().all(Result::is_ok), "{earlier:?}");
}
