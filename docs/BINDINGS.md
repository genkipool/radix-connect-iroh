# Binding APIs

Both bindings wrap the same Rust `Session` (`crates/radix-connect-iroh`), so the
wallet and the Connector Extension run identical protocol code.

One session per link and per side. The wallet uses `role = wallet` (it dials), the
Connector Extension uses `role = connector` (it waits for the wallet). The session
reconnects by itself; the host only reads events and sends messages.

Keep a loop reading `nextEvent()` for the whole life of a session: a message is
confirmed to the sender only when the host takes it, so a host that stops reading makes
the peer's sends time out.

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
    var relayUrl: String,
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
    suspend fun nextEvent(): IrohSessionEvent? // null once shut down; taking a Message confirms it to the peer
    suspend fun networkChanged()              // call from ConnectivityManager callbacks
    suspend fun shutdown()                    // tells the peer, idempotent; then close()
}

fun irohDefaultRelayUrl(): String
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
import init, { IrohSession, defaultRelayUrl, endpointId, setLogger } from '@radixdlt/radix-connect-iroh'
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
  static start(password: Uint8Array, role: IrohRole, relayUrl: string, ackTimeoutMs?: number): Promise<IrohSession>
  localEndpointId(): string
  peerEndpointId(): string
  state(): IrohConnectionState
  diagnostics(): IrohDiagnostics // connectivity snapshot; `summary` is one log line
  send(message: string): Promise<void>
  nextEvent(): Promise<IrohSessionEvent | undefined> // undefined once shut down; taking a message confirms it
  shutdown(): Promise<void>
  free(): void
}
function defaultRelayUrl(): string
function endpointId(password: Uint8Array, role: IrohRole): string
function validateRelayUrl(relayUrl: string): string | undefined // undefined when usable
function setLogger(logger: (level: string, target: string, message: string) => void, maxLevel: 'error' | 'warn' | 'info' | 'debug' | 'trace'): void
```

## Diagnostics

`diagnostics()` returns a snapshot that holds no secrets: role, both endpoint ids, the
relay URL, whether this end is connected to the relay (and the relay's last error),
the connection state, the path (direct or relay) and its RTT while connected, failed
attempts since the last connection, the last error (dialing, handshake, why a
connection ended, a failed send...) and how long the connection has been up, plus a
one-line `summary`. Hosts should log the summary on every state change and on send
failures, and show the fields on their debug/diagnostics screens.

The library's own logs (routed with `irohInstallLogSink` / `setLogger`) explain the
same events as they happen, e.g. "not connected to the relay: the peer cannot reach
this end", "dialing the connector timed out: is it running, with iroh, on the same
relay?", "connection to the peer ended reason=replaced by a newer connection".

### Reading a snapshot

| What you see | What it usually means |
|---|---|
| `relay … (NOT connected)` | No internet, the relay is down or blocked, or a wrong relay URL. Nothing can connect. |
| wallet `state=connecting`, `failed_attempts` growing, `last_error="dial: timed out …"` | The connector is not running, has iroh disabled, or uses another relay. |
| `last_error="connection ended: the peer rejected this endpoint as unauthorized"` | The two ends hold different passwords for the link (re-link). |
| `last_error="connection ended: replaced by a newer connection"` | Harmless: the same device reconnected (e.g. network change). |
| `path=relay` on a phone that could go direct | Normal behind strict NATs; the connection is still end-to-end encrypted. |
