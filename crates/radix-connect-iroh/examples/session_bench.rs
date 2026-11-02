//! Measures a link end to end through the real [`Session`] API: both ends run in this
//! process, as two independent iroh endpoints that only meet through the relays, exactly
//! as the wallet and the Connector Extension do.
//!
//! ```text
//! cargo run --release --features bench-utils --example session_bench -- connect   [trials]
//! cargo run --release --features bench-utils --example session_bench -- burst     [rounds] [messages] [bytes]
//! cargo run --release --features bench-utils --example session_bench -- roundtrip [rounds]
//! ```
//!
//! - `connect`: a fresh wallet session per trial (a cold start, as after the app's
//!   sessions were stopped in the background) until it is connected to a connector
//!   that is already listening.
//! - `burst`: `messages` sent at once in each direction over one connection, until every
//!   one is confirmed (the receiver hands them to its host one at a time).
//! - `roundtrip`: one message to the connector and its echo back.
//!
//! The connector reaches the wallet only through the relay, as the browser does (needs the
//! `bench-utils` feature: `--features bench-utils`). n0's public relays by default, as in
//! production; `RADIX_CONNECT_RELAY=<url>` uses a
//! custom one. Each run uses a fresh random link, so it never touches a real one. Results
//! are printed as one `SUMMARY` line per measurement (milliseconds: n, min, median, p90,
//! max), for the measurement log.

use std::error::Error as StdError;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use radix_connect_iroh::{
    ConnectionPassword, ConnectionState, Role, Session, SessionConfig, SessionEvent,
};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

type BoxError = Box<dyn StdError + Send + Sync>;

/// How long a connector waits for its relay before the wallet starts dialing.
const RELAY_WAIT: Duration = Duration::from_secs(20);
/// After the relay is up, how long the address lookup record takes to be found reliably.
const PUBLISH_SETTLE: Duration = Duration::from_secs(3);
/// Upper bound for one wallet connecting, a burst or a round trip.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// What to measure, read from the command line before anything is started.
enum Bench {
    Connect {
        trials: usize,
    },
    Burst {
        rounds: usize,
        messages: usize,
        bytes: usize,
    },
    Roundtrip {
        rounds: usize,
    },
}

impl Bench {
    fn from_args() -> Result<Self, BoxError> {
        let usage = "usage: session_bench <connect [trials] | burst [rounds] [messages] [bytes] | roundtrip [rounds]>";
        let mut args = std::env::args().skip(1);
        let mode = args.next().ok_or(usage)?;
        let mut number = |default: usize| -> Result<usize, BoxError> {
            args.next()
                .map_or(Ok(default), |arg| arg.parse().map_err(|_| usage.into()))
        };
        match mode.as_str() {
            "connect" => Ok(Self::Connect {
                trials: number(10)?,
            }),
            "burst" => Ok(Self::Burst {
                rounds: number(10)?,
                messages: number(5)?,
                bytes: number(200)?,
            }),
            "roundtrip" => Ok(Self::Roundtrip {
                rounds: number(20)?,
            }),
            _ => Err(usage.into()),
        }
    }
}

async fn run() -> Result<(), BoxError> {
    let bench = Bench::from_args()?;
    let config = SessionConfig::for_relay(std::env::var("RADIX_CONNECT_RELAY").ok().as_deref())?;
    let password = random_password();
    let connector = Arc::new(start_connector(&password, &config).await?);
    let echo = matches!(bench, Bench::Roundtrip { .. });
    tokio::spawn(serve_connector(Arc::clone(&connector), echo));

    let result = match bench {
        Bench::Connect { trials } => connect(&password, &config, trials).await,
        Bench::Burst {
            rounds,
            messages,
            bytes,
        } => burst(&password, &config, &connector, rounds, messages, bytes).await,
        Bench::Roundtrip { rounds } => roundtrip(&password, &config, rounds).await,
    };
    connector.close().await;
    result
}

/// A link of its own for this run: never one a real wallet or extension holds.
fn random_password() -> ConnectionPassword {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("{:?}{}", SystemTime::now(), std::process::id()).as_bytes());
    ConnectionPassword::from_bytes(*hasher.finalize().as_bytes())
}

async fn start_connector(
    password: &ConnectionPassword,
    config: &SessionConfig,
) -> Result<Session, BoxError> {
    let started = Instant::now();
    // As the Connector Extension: a browser has no UDP, so its connections always go through
    // the relay. Nobody to knock: the wallet of this link does not exist yet.
    let connector_config = config.clone().without_knocks().relay_only_for_benchmarks();
    let session = Session::start(password, Role::Connector, connector_config).await?;
    let waiting = async {
        while !session.diagnostics().relay_connected {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::time::timeout(RELAY_WAIT, waiting)
        .await
        .map_err(|_| "the connector did not reach its relay")?;
    println!(
        "connector on its relay after {} ms",
        started.elapsed().as_millis()
    );
    tokio::time::sleep(PUBLISH_SETTLE).await;
    Ok(session)
}

/// The connector's host: takes every message, and echoes it back for `roundtrip`.
async fn serve_connector(session: Arc<Session>, echo: bool) {
    while let Some(event) = session.next_event().await {
        if let (true, SessionEvent::Message(message)) = (echo, event) {
            let session = Arc::clone(&session);
            tokio::spawn(async move {
                let _ = session.send(&message).await;
            });
        }
    }
}

/// Starts a wallet session and waits until it is connected; its other events go to
/// `messages`.
async fn connected_wallet(
    password: &ConnectionPassword,
    config: &SessionConfig,
    messages: mpsc::UnboundedSender<String>,
) -> Result<Arc<Session>, BoxError> {
    let session = Arc::new(Session::start(password, Role::Wallet, config.clone()).await?);
    let waiting = async {
        loop {
            match session.next_event().await {
                Some(SessionEvent::StateChanged(ConnectionState::Connected)) => return Ok(()),
                Some(_) => {}
                None => return Err("the wallet session ended before connecting"),
            }
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, waiting)
        .await
        .map_err(|_| "the wallet did not connect in time")??;
    let reader = Arc::clone(&session);
    tokio::spawn(async move {
        while let Some(event) = reader.next_event().await {
            if let SessionEvent::Message(message) = event {
                let _ = messages.send(message);
            }
        }
    });
    Ok(session)
}

async fn connect(
    password: &ConnectionPassword,
    config: &SessionConfig,
    trials: usize,
) -> Result<(), BoxError> {
    let mut times = Vec::with_capacity(trials);
    for trial in 1..=trials {
        let started = Instant::now();
        let (messages, _ignored) = mpsc::unbounded_channel();
        let wallet = connected_wallet(password, config, messages).await?;
        let elapsed = started.elapsed();
        println!("trial {trial}: connected in {} ms", elapsed.as_millis());
        times.push(elapsed);
        wallet.close().await;
        // The connector notices the old connection is gone before the next one.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    summary("connect", &mut times);
    Ok(())
}

async fn burst(
    password: &ConnectionPassword,
    config: &SessionConfig,
    connector: &Arc<Session>,
    rounds: usize,
    messages: usize,
    bytes: usize,
) -> Result<(), BoxError> {
    let (sink, _ignored) = mpsc::unbounded_channel();
    let wallet = connected_wallet(password, config, sink).await?;
    let payload = "x".repeat(bytes);
    let mut to_connector = Vec::with_capacity(rounds);
    let mut to_wallet = Vec::with_capacity(rounds);
    for round in 1..=rounds {
        let up = send_all(&wallet, &payload, messages).await?;
        let down = send_all(connector, &payload, messages).await?;
        println!(
            "round {round}: {messages} x {bytes} B wallet->connector {} ms, connector->wallet {} ms",
            up.as_millis(),
            down.as_millis()
        );
        to_connector.push(up);
        to_wallet.push(down);
    }
    summary(
        &format!("burst {messages}x{bytes}B wallet->connector"),
        &mut to_connector,
    );
    summary(
        &format!("burst {messages}x{bytes}B connector->wallet"),
        &mut to_wallet,
    );
    wallet.close().await;
    Ok(())
}

/// Sends `count` copies of `payload` at once and waits until every one is confirmed.
async fn send_all(
    session: &Arc<Session>,
    payload: &str,
    count: usize,
) -> Result<Duration, BoxError> {
    let started = Instant::now();
    let mut sends = JoinSet::new();
    for _ in 0..count {
        let session = Arc::clone(session);
        let payload = payload.to_owned();
        sends.spawn(async move { session.send(&payload).await });
    }
    let all = async {
        while let Some(sent) = sends.join_next().await {
            sent??;
        }
        Ok::<(), BoxError>(())
    };
    tokio::time::timeout(STEP_TIMEOUT, all)
        .await
        .map_err(|_| "a burst did not complete in time")??;
    Ok(started.elapsed())
}

async fn roundtrip(
    password: &ConnectionPassword,
    config: &SessionConfig,
    rounds: usize,
) -> Result<(), BoxError> {
    let (sink, mut echoes) = mpsc::unbounded_channel();
    let wallet = connected_wallet(password, config, sink).await?;
    let mut times = Vec::with_capacity(rounds);
    for round in 1..=rounds {
        let message = format!("{{\"bench\":{round}}}");
        let started = Instant::now();
        wallet.send(&message).await?;
        let echoed = async {
            while let Some(echo) = echoes.recv().await {
                if echo == message {
                    return Ok(());
                }
            }
            Err("the wallet stopped receiving")
        };
        tokio::time::timeout(STEP_TIMEOUT, echoed)
            .await
            .map_err(|_| "no echo in time")??;
        times.push(started.elapsed());
    }
    summary("roundtrip", &mut times);
    wallet.close().await;
    Ok(())
}

/// Prints `n, min, median, p90, max` in milliseconds.
fn summary(name: &str, times: &mut [Duration]) {
    times.sort();
    let at = |fraction: f64| {
        // Nearest rank: the smallest value with at least `fraction` of the samples at or below it.
        let rank = (fraction * times.len() as f64).ceil() as usize;
        times
            .get(rank.saturating_sub(1))
            .map_or(0, Duration::as_millis)
    };
    println!(
        "SUMMARY {name}: n={} min={} median={} p90={} max={}",
        times.len(),
        at(0.0001),
        at(0.5),
        at(0.9),
        at(1.0)
    );
}
