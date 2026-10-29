# Binding APIs

Both bindings wrap the same Rust `Session` (`crates/radix-connect-iroh`), so the
wallet and the Connector Extension run identical protocol code.

One session per link and per side. The wallet uses `role = wallet` (it dials), the
Connector Extension uses `role = connector` (it waits for the wallet). The session
reconnects by itself; the host only reads events and sends messages.

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
    suspend fun send(message: String)         // throws IrohException; NotConnected immediately
    suspend fun nextEvent(): IrohSessionEvent? // null once shut down
    suspend fun networkChanged()              // call from ConnectivityManager callbacks
    suspend fun shutdown()                    // tells the peer, idempotent; then close()
}

fun irohDefaultRelayUrl(): String
fun irohEndpointId(password: ByteArray, role: IrohRole): String

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
import wasmUrl from '@radixdlt/radix-connect-iroh/radix_connect_iroh_wasm_bg.wasm?url'

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
  send(message: string): Promise<void>
  nextEvent(): Promise<IrohSessionEvent | undefined> // undefined once shut down
  shutdown(): Promise<void>
  free(): void
}
function defaultRelayUrl(): string
function endpointId(password: Uint8Array, role: IrohRole): string
function setLogger(logger: (level: string, target: string, message: string) => void, maxLevel: 'error' | 'warn' | 'info' | 'debug' | 'trace'): void
```
