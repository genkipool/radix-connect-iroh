// Connector side of the cross-implementation test (scripts/e2e.sh): the wasm build,
// run by Node through the same WebSocket-only code path as in the browser.
// Waits for the wallet, receives one message, answers it and exits.
import { IrohSession, setLogger } from '../dist-nodejs/radix_connect_iroh.js'

const [passwordHex, relayUrl] = process.argv.slice(2)
const password = Uint8Array.from(Buffer.from(passwordHex, 'hex'))
setLogger((level, target, message) => console.error(`[${level}] ${target}: ${message}`), 'info')

const session = await IrohSession.start(password, 'connector', relayUrl, 10_000)
console.log(`connector ${session.localEndpointId()} waiting for ${session.peerEndpointId()}`)
const timeout = setTimeout(() => {
  console.error('timed out')
  process.exit(2)
}, 60_000)

for (;;) {
  const event = await session.nextEvent()
  if (!event) break
  if (event.type === 'stateChanged') console.log(`state ${event.state}`)
  if (event.type === 'message') {
    const request = JSON.parse(event.message)
    console.log(`received ${event.message}`)
    await session.send(JSON.stringify({ echo: request, from: 'wasm-connector' }))
    console.log('answered')
    break
  }
}
clearTimeout(timeout)
await session.shutdown()
session.free()
