# Binding APIs

Both bindings wrap the same Rust `Session` (`crates/radix-connect-iroh`), so the
wallet and the Connector Extension run identical protocol code.

One session per link and per side. The wallet uses `role = wallet` (it dials), the
Connector Extension uses `role = connector` (it waits for the wallet). The session
reconnects by itself; the host only reads events and sends messages.

Keep a loop reading `nextEvent()` for the whole life of a session: a message is
confirmed to the sender only when the host takes it, so a host that stops reading makes
the peer's sends time out.

Call `networkChanged()` on every connectivity change **and** whenever the app returns
to the foreground or the machine wakes up: a wallet waiting to redial dials at once
(and retries quickly again for 2 minutes instead of every 30 s), and the current
connection is checked, so one that died while the app was in the background is dropped
and redialed within seconds instead of looking connected until it times out (30 s).
Calls in quick succession are cheap: they share one check.

Messages are the same UTF-8 JSON strings the WebRTC data channel carries after
reassembly (wallet interactions, responses, `linkClient`, `accountList`, ledger
messages). No chunking, no `packageType` envelope.

## Kotlin (Android) — `com.radixdlt.connect.iroh`

Artifact: `com.radixdlt.connect:radix-connect-iroh-android:<version>` (AAR with
`libradix_connect_iroh_uniffi.so` for arm64-v8a, armeabi-v7a, x86_64, x86; depends
on JNA and kotlinx-coroutines).

```kotlin
enum class IrohRole { WALLET, CONNECTOR }
enum class IrohConnectionState { CONNECTING, CONNECTED, DISCONNECTED }
sealed class IrohSessionEvent {
    data class StateChanged(val state: IrohConnectionState) : IrohSessionEvent()
    data class Message(val message: String) : IrohSessionEvent()
}
data class IrohSessionConfig(
    var relayUrl: String? = null,             // null = n0's public relays (default)
    var ackTimeoutMs: ULong = 10_000uL,
    var maxMessageSize: ULong = 8_388_608uL,
)
sealed class IrohException : Exception() {
    // InvalidPassword, InvalidRelayUrl(reason), Bind(reason), NotConnected, Timeout,
    // MessageTooLarge(size, max), Rejected, ConnectionLost(reason), Closed, Internal(reason)
}

class IrohSession : AutoCloseable {          // close() frees the native object
    companion object {
        suspend fun start(password: ByteArray, role: IrohRole, config: IrohSessionConfig): IrohSession
    }
    fun localEndpointId(): String
    fun peerEndpointId(): String
    fun state(): IrohConnectionState
    fun diagnostics(): IrohDiagnostics        // connectivity snapshot; `summary` is one log line
    suspend fun send(message: String)         // throws IrohException; NotConnected immediately
    suspend fun nextEvent(): IrohSessionEvent? // null once shut down; taking a Message confirms it to the peer;
                                               // states come as their latest value
    suspend fun networkChanged()              // call from ConnectivityManager callbacks and on app resume
    suspend fun shutdown()                    // tells the peer, idempotent; then close()
}

fun irohPublicRelayUrls(): List<String>  // for display
fun irohEndpointId(password: ByteArray, role: IrohRole): String
fun irohValidateRelayUrl(relayUrl: String): String? // null when usable, else the reason

enum class IrohLogLevel { ERROR, WARN, INFO, DEBUG, TRACE }
interface IrohLogSink { fun log(level: IrohLogLevel, target: String, message: String) }
fun irohInstallLogSink(sink: IrohLogSink, maxLevel: IrohLogLevel)

object RadixConnectIrohAndroid {
    // Once per process, before the first session: lets iroh read the system DNS.
    fun installAndroidContext(context: Context)
}
```

## TypeScript (browser, wasm) — `@radixdlt/radix-connect-iroh`

`wasm-bindgen --target web` output. Extension pages need
`script-src 'self' 'wasm-unsafe-eval'` in the manifest CSP.

```ts
import init, { IrohSession, publicRelayUrls, endpointId, setLogger } from '@radixdlt/radix-connect-iroh'
import wasmUrl from '@radixdlt/radix-connect-iroh/radix_connect_iroh_bg.wasm?url'

await init({ module_or_path: wasmUrl }) // once per page

type IrohRole = 'wallet' | 'connector'
type IrohConnectionState = 'connecting' | 'connected' | 'disconnected'
type IrohSessionEvent =
  | { type: 'stateChanged'; state: IrohConnectionState }
  | { type: 'message'; message: string }
type IrohErrorCode =
  | 'invalidPassword' | 'invalidRelayUrl' | 'bind' | 'notConnected' | 'timeout'
  | 'messageTooLarge' | 'rejected' | 'connectionLost' | 'closed' | 'internal'
// Rejections are `Error` objects with an extra `code: IrohErrorCode` property.

class IrohSession {
  // relayUrl undefined/null = n0's public relays (default)
  static start(password: Uint8Array, role: IrohRole, relayUrl?: string | null, ackTimeoutMs?: number | null): Promise<IrohSession>
  localEndpointId(): string
  peerEndpointId(): string
  state(): IrohConnectionState
  diagnostics(): IrohDiagnostics // connectivity snapshot; `summary` is one log line
  send(message: string): Promise<void>
  nextEvent(): Promise<IrohSessionEvent | undefined> // undefined once shut down; taking a message confirms it
  networkChanged(): Promise<void> // on `online`/`offline`, wake-up, extension becoming active
  shutdown(): Promise<void>
  free(): void
}
function publicRelayUrls(): string[] // for display
function endpointId(password: Uint8Array, role: IrohRole): string
function validateRelayUrl(relayUrl: string): string | undefined // undefined when usable
function setLogger(logger: (level: string, target: string, message: string) => void, maxLevel: 'error' | 'warn' | 'info' | 'debug' | 'trace'): void
```

## Diagnostics

`diagnostics()` returns a snapshot that holds no secrets: role, both endpoint ids, the
relay in use (the custom one, or the public relay this end connected to) and whether
the public relays are used, whether this end is connected to the relay (and the relay's last error),
the connection state, the path (direct or relay) and its RTT while connected, failed
attempts since the last connection, the last error (dialing, handshake, why a
connection ended, a failed send...) and how long the connection has been up, whether
another holder of the link's key took this end's place on the relay (`keyCollision`
in both bindings, added after 0.1.0), plus a one-line `summary`. Hosts should log the summary on every state change and on send failures,
and show the fields on their debug/diagnostics screens. The library itself logs it on
every connect and disconnect (`connectivity snapshot`).

The library's own logs (routed with `irohInstallLogSink` / `setLogger`) explain the
same events as they happen; `docs/PROTOCOL.md` §10 lists them. Each line is the
message followed by `key=value` fields and the context it happened in:

```text
connected to the peer path=relay rtt_ms=42 setup_ms=812 attempt=2 session=1 role=wallet local=4d99dc649e peer=efcc89cfbf conn=1
could not send a message to the peer bytes=2048 outcome=timeout phase=confirmation elapsed_ms=10001 timeout_ms=10000 total_ms=10014 error="the peer did not confirm the message in time" session=1 role=wallet local=4d99dc649e peer=efcc89cfbf send_seq=7 conn=1
```

`session=` ties the lines of one link together (several links log in parallel),
`conn=` one connection, `send_seq=`/`recv_seq=` one message. Lines never contain the
password, keys, message contents or IP addresses (redacted as `<ip>`, also in iroh's own
lines), so they can be exported and shared. The bindings install their subscriber when
the first session starts, even without a sink: it is what notices a key collision.

### Reading a snapshot

| What you see | What it usually means |
|---|---|
| `relay … (NOT connected)` | No internet, the relay is down or blocked, or a wrong relay URL. Nothing can connect. |
| wallet `state=connecting`, `failed_attempts` growing, `last_error="dial: timed out …"` | The connector is not running, has iroh disabled, or uses another relay. |
| `last_error="connection ended: the peer rejected this endpoint as unauthorized"` | The two ends hold different passwords for the link (re-link). |
| `last_error="connection ended: the connector accepted a newer connection with this link's wallet key"` | Another wallet (device or app instance) with this link connected; this one backs off (up to 5 min) so the two do not keep taking the link from each other. |
| `KEY COLLISION` / `keyCollision = true` | Another device or app instance holds this link and connected to the same relay after this end: the relay delivers to it, so the peer cannot reach this end. Close one of them (or re-link). |
| `last_error="connection ended: no answer to a liveness check"` | The connection died (e.g. while the app was in the background) and was dropped when the host reported a wake-up or a network change; the wallet redials at once. |
| wallet `failed_attempts` growing slowly (one every ~40 s) | The connector has been unreachable for over 2 minutes; the wallet retries every 30 s until `networkChanged()` (foreground, network change) makes it dial at once. |
| `path=relay` on a phone that could go direct | Normal behind strict NATs; the connection is still end-to-end encrypted. |
