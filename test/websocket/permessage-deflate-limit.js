'use strict'

const { test } = require('node:test')
const assert = require('node:assert')
const { once } = require('node:events')
const http = require('node:http')
const crypto = require('node:crypto')
const { deflateRawSync } = require('node:zlib')
const { setTimeout: sleep } = require('node:timers/promises')
const { WebSocketServer } = require('ws')
const { WebSocket, Agent, Dispatcher } = require('../..')

/**
 * Races a promise against a timeout without leaving a pending timer behind.
 * Resolves to `null` when the timeout wins.
 * @param {Promise<any>} promise
 * @param {number} ms
 */
async function raceTimeout (promise, ms) {
  const ac = new AbortController()

  try {
    return await Promise.race([promise, sleep(ms, null, { signal: ac.signal })])
  } finally {
    ac.abort()
  }
}

/**
 * Creates a WebSocket frame header.
 * @param {object} options
 * @param {number} options.opcode - Frame opcode (1=text, 2=binary)
 * @param {boolean} options.fin - Final frame flag
 * @param {boolean} options.rsv1 - RSV1 flag (compression)
 * @param {number} options.length - Payload length announced by the frame
 * @returns {Buffer}
 */
function createWebSocketFrameHeader ({ opcode, fin = true, rsv1 = false, length }) {
  let header

  if (length > 65535) {
    header = Buffer.alloc(10)
    header[1] = 127
    header.writeBigUInt64BE(BigInt(length), 2)
  } else if (length > 125) {
    header = Buffer.alloc(4)
    header[1] = 126
    header.writeUInt16BE(length, 2)
  } else {
    header = Buffer.alloc(2)
    header[1] = length
  }

  // First byte: FIN + RSV1 + opcode
  header[0] = (fin ? 0x80 : 0x00) | (rsv1 ? 0x40 : 0x00) | opcode

  return header
}

/**
 * Creates a WebSocket frame.
 * @param {object} options
 * @param {Buffer} options.payload - Frame payload
 * @returns {Buffer}
 */
function createWebSocketFrame ({ payload, ...options }) {
  return Buffer.concat([createWebSocketFrameHeader({ ...options, length: payload.length }), payload])
}

/**
 * Creates a compressed payload using DEFLATE raw.
 * @param {number} targetSize - Target decompressed size in bytes
 * @returns {Buffer}
 */
function createCompressedPayload (targetSize) {
  // Create highly compressible data (repeated 'A' characters)
  const data = Buffer.alloc(targetSize, 0x41)
  return deflateRawSync(data)
}

/**
 * Starts a minimal (malicious) WebSocket server that accepts the
 * permessage-deflate extension and hands the raw socket to `onUpgrade`.
 * @returns {Promise<{ server: import('node:http').Server, closeCode: Promise<number|null> }>}
 */
async function createRawServer (t, onUpgrade) {
  const server = http.createServer()
  const sockets = new Set()

  let resolveCloseCode
  const closeCode = new Promise((resolve) => { resolveCloseCode = resolve })

  server.on('upgrade', (req, socket) => {
    sockets.add(socket)
    socket.on('error', () => {})

    // Record the status code of the close frame sent by the client.
    let received = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      received = Buffer.concat([received, chunk])

      if (received.length < 2) {
        return
      }

      const opcode = received[0] & 0x0F
      const length = received[1] & 0x7F

      if (opcode === 0x8 && length >= 2 && received.length >= 6 + length) {
        const mask = received.subarray(2, 6)
        const code = ((received[6] ^ mask[0]) << 8) | (received[7] ^ mask[1])
        resolveCloseCode(code)
      }
    })
    socket.on('close', () => resolveCloseCode(null))

    const key = req.headers['sec-websocket-key']
    const accept = crypto
      .createHash('sha1')
      .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      .digest('base64')

    socket.write([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${accept}`,
      'Sec-WebSocket-Extensions: permessage-deflate',
      '', ''
    ].join('\r\n'))

    onUpgrade(socket)
  })

  server.listen(0)
  await once(server, 'listening')

  t.after(() => {
    for (const socket of sockets) {
      socket.destroy()
    }
    server.close()
  })

  return { server, closeCode }
}

/**
 * A dispatcher that does not extend DispatcherBase (and therefore does not
 * expose `webSocketOptions`), e.g. a custom dispatcher or a global dispatcher
 * installed by another copy of undici.
 */
class ForwardingDispatcher extends Dispatcher {
  #target

  constructor (target) {
    super()
    this.#target = target
  }

  dispatch (opts, handler) {
    return this.#target.dispatch(opts, handler)
  }

  close (...args) {
    return this.#target.close(...args)
  }

  destroy (...args) {
    return this.#target.destroy(...args)
  }
}

test('Compressed message under limit decompresses successfully', async (t) => {
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: true
  })

  t.after(() => server.close())

  await once(server, 'listening')

  server.on('connection', (ws) => {
    // Send 1 KB of data (well under any reasonable limit)
    ws.send(Buffer.alloc(1024, 0x41), { binary: true })
  })

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

  const [event] = await once(client, 'message')
  assert.strictEqual(event.data.size, 1024)
  client.close()
})

test('Agent webSocketOptions.maxPayloadSize is read correctly', async (t) => {
  const customLimit = 128 * 1024 * 1024 // 128 MB
  const agent = new Agent({
    webSocket: {
      maxPayloadSize: customLimit
    }
  })

  t.after(() => agent.close())

  // Verify the option is stored and retrievable
  assert.strictEqual(agent.webSocketOptions.maxPayloadSize, customLimit)
})

test('Agent with default webSocketOptions uses 128 MB limit', async (t) => {
  const agent = new Agent()

  t.after(() => agent.close())

  // Default should be 128 MB
  assert.strictEqual(agent.webSocketOptions.maxPayloadSize, 128 * 1024 * 1024)
})

test('Custom maxPayloadSize allows messages under limit', async (t) => {
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: true
  })

  t.after(() => server.close())
  await once(server, 'listening')

  const dataSize = 512 * 1024 // 512 KB

  server.on('connection', (ws) => {
    ws.send(Buffer.alloc(dataSize, 0x41), { binary: true })
  })

  // Set custom limit of 1 MB via Agent
  const agent = new Agent({
    webSocket: {
      maxPayloadSize: 1 * 1024 * 1024
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  const [event] = await once(client, 'message')
  assert.strictEqual(event.data.size, dataSize, 'Message under limit should be received')
  client.close()
})

test('Messages at exactly the limit succeed', async (t) => {
  const limit = 1 * 1024 * 1024 // 1 MB
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: true
  })

  t.after(() => server.close())
  await once(server, 'listening')

  server.on('connection', (ws) => {
    ws.send(Buffer.alloc(limit, 0x41), { binary: true })
  })

  const agent = new Agent({
    webSocket: {
      maxPayloadSize: limit
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  const [event] = await once(client, 'message')
  assert.strictEqual(event.data.size, limit, 'Message at exactly the limit should succeed')
  client.close()
})

test('Compressed frame payload over wire-size limit is rejected', async (t) => {
  const limit = 64 * 1024
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: true
  })

  t.after(() => server.close())
  await once(server, 'listening')

  let payload = null
  for (let i = 0; i < 10; i++) {
    const candidate = crypto.randomFillSync(Buffer.alloc(limit))
    if (deflateRawSync(candidate).length > limit) {
      payload = candidate
      break
    }
  }

  assert.ok(payload, 'Expected incompressible payload with compressed wire size over the limit')

  let messageReceived = false

  server.on('connection', (ws) => {
    ws.send(payload, { binary: true, compress: true })
  })

  const agent = new Agent({
    webSocket: {
      maxPayloadSize: limit
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  client.addEventListener('message', () => {
    messageReceived = true
  })

  await raceTimeout(once(client, 'close'), 5000)

  assert.strictEqual(messageReceived, false, 'Compressed frame over wire-size limit should be rejected')
  assert.strictEqual(client.readyState, WebSocket.CLOSED, 'Connection should be closed after exceeding limit')
})

test('Messages over the limit are rejected', async (t) => {
  const limit = 1 * 1024 * 1024 // 1 MB
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: true
  })

  t.after(() => server.close())
  await once(server, 'listening')

  let messageReceived = false
  let closeEvent = null

  server.on('connection', (ws) => {
    // Send 2 MB of data, which exceeds the 1 MB limit
    ws.send(Buffer.alloc(2 * 1024 * 1024, 0x41), { binary: true })
  })

  const agent = new Agent({
    webSocket: {
      maxPayloadSize: limit
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  client.addEventListener('message', () => {
    messageReceived = true
  })

  client.addEventListener('close', (event) => {
    closeEvent = event
  })

  // Wait for connection to close (should happen when limit is exceeded)
  await raceTimeout(once(client, 'close'), 5000)

  assert.strictEqual(messageReceived, false, 'Message over limit should be rejected')
  assert.ok(closeEvent !== null, 'Close event should have been emitted')
  assert.strictEqual(client.readyState, WebSocket.CLOSED, 'Connection should be closed after exceeding limit')
})

test('Limit can be disabled by setting maxPayloadSize to 0', async (t) => {
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: true
  })

  t.after(() => server.close())
  await once(server, 'listening')

  const dataSize = 100 * 1024 * 1024 // 100 MB

  server.on('connection', (ws) => {
    ws.send(Buffer.alloc(dataSize, 0x41), { binary: true })
  })

  // Set limit to 0 (disabled)
  const agent = new Agent({
    webSocket: {
      maxPayloadSize: 0
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  // Use a timeout since large message takes time
  const result = await raceTimeout(once(client, 'message'), 10000)

  if (result) {
    assert.strictEqual(result[0].data.size, dataSize, 'Large message should be received when limit is disabled')
    client.close()
  } else {
    assert.fail('Test timed out waiting for large message')
  }
})

test('Fragmented compressed payload over total limit is rejected', async (t) => {
  const limit = 1 * 1024 * 1024 // 1 MB
  const fragmentSize = 768 * 1024 // 768 KB
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: true
  })

  t.after(() => server.close())
  await once(server, 'listening')

  let messageReceived = false

  server.on('connection', (ws) => {
    ws.send(Buffer.alloc(fragmentSize, 0x41), {
      binary: true,
      compress: true,
      fin: false
    })

    ws.send(Buffer.alloc(fragmentSize, 0x41), {
      binary: true,
      compress: true,
      fin: true
    })
  })

  const agent = new Agent({
    webSocket: {
      maxPayloadSize: limit
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  client.addEventListener('message', () => {
    messageReceived = true
  })

  await raceTimeout(once(client, 'close'), 5000)

  assert.strictEqual(messageReceived, false, 'Fragmented compressed message over total limit should be rejected')
  assert.strictEqual(client.readyState, WebSocket.CLOSED, 'Connection should be closed after exceeding limit')
})

test('Raw uncompressed payload over immediate limit is rejected', async (t) => {
  const limit = 100
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: false // Disable compression
  })

  t.after(() => server.close())
  await once(server, 'listening')

  let messageReceived = false

  server.on('connection', (ws) => {
    // Send 101 bytes uncompressed so the inline payload length path is used.
    ws.send(Buffer.alloc(101, 0x41), { binary: true })
  })

  const agent = new Agent({
    webSocket: {
      maxPayloadSize: limit
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  client.addEventListener('message', () => {
    messageReceived = true
  })

  await raceTimeout(once(client, 'close'), 5000)

  assert.strictEqual(messageReceived, false, 'Raw uncompressed message over limit should be rejected')
  assert.strictEqual(client.readyState, WebSocket.CLOSED, 'Connection should be closed after exceeding limit')
})

test('Raw uncompressed payload over 16-bit extended limit is rejected', async (t) => {
  const limit = 1 * 1024 // 1 KB
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: false // Disable compression
  })

  t.after(() => server.close())
  await once(server, 'listening')

  let messageReceived = false

  server.on('connection', (ws) => {
    // Send 2 KB uncompressed so the extended 16-bit payload length path is used.
    ws.send(Buffer.alloc(2 * 1024, 0x41), { binary: true })
  })

  const agent = new Agent({
    webSocket: {
      maxPayloadSize: limit
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  client.addEventListener('message', () => {
    messageReceived = true
  })

  await raceTimeout(once(client, 'close'), 5000)

  assert.strictEqual(messageReceived, false, 'Raw uncompressed message over limit should be rejected')
  assert.strictEqual(client.readyState, WebSocket.CLOSED, 'Connection should be closed after exceeding limit')
})

test('Raw uncompressed payload over 64-bit extended limit is rejected', async (t) => {
  const limit = 1 * 1024 * 1024 // 1 MB
  const server = new WebSocketServer({
    port: 0,
    perMessageDeflate: false // Disable compression
  })

  t.after(() => server.close())
  await once(server, 'listening')

  let messageReceived = false

  server.on('connection', (ws) => {
    // Send 2 MB uncompressed so the extended 64-bit payload length path is used.
    ws.send(Buffer.alloc(2 * 1024 * 1024, 0x41), { binary: true })
  })

  const agent = new Agent({
    webSocket: {
      maxPayloadSize: limit
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  client.addEventListener('message', () => {
    messageReceived = true
  })

  await raceTimeout(once(client, 'close'), 5000)

  assert.strictEqual(messageReceived, false, 'Raw uncompressed message over limit should be rejected')
  assert.strictEqual(client.readyState, WebSocket.CLOSED, 'Connection should be closed after exceeding limit')
})

test('Decompression bomb is mitigated via raw WebSocket handshake', async (t) => {
  // This test validates the fix using a technique similar to the original PoC
  // by creating a minimal malicious server that sends a compressed payload
  let messageReceived = false

  const { server, closeCode } = await createRawServer(t, (socket) => {
    // Send a small payload that decompresses to ~10 MB
    setTimeout(() => {
      const bomb = createCompressedPayload(10 * 1024 * 1024)
      const frame = createWebSocketFrame({ opcode: 2, rsv1: true, payload: bomb })
      socket.write(frame)
    }, 100)
  })

  const agent = new Agent({
    webSocket: {
      maxPayloadSize: 1 * 1024 * 1024 // 1 MB limit
    }
  })

  t.after(() => agent.close())

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher: agent })

  client.addEventListener('message', () => {
    messageReceived = true
  })

  // Wait for the connection to close
  const closed = await raceTimeout(once(client, 'close'), 5000)

  // The message should NOT have been received due to size limit
  assert.ok(closed, 'Connection should be closed after exceeding limit')
  assert.strictEqual(messageReceived, false)
  assert.strictEqual(await closeCode, 1009, 'Client should close with 1009 (Message Too Big)')
})

test('Decompression bomb is mitigated with the default configuration', async (t) => {
  // No dispatcher is configured: the default 128 MB limit must apply.
  let messageReceived = false

  const { server, closeCode } = await createRawServer(t, (socket) => {
    setTimeout(() => {
      // ~130 KB on the wire, 129 MB once inflated.
      const bomb = createCompressedPayload(129 * 1024 * 1024)
      socket.write(createWebSocketFrame({ opcode: 2, rsv1: true, payload: bomb }))
    }, 100)
  })

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

  client.addEventListener('message', () => {
    messageReceived = true
  })

  const closed = await raceTimeout(once(client, 'close'), 15000)

  assert.ok(closed, 'Connection should be closed after exceeding the default limit')
  assert.strictEqual(messageReceived, false)
  assert.strictEqual(await closeCode, 1009, 'Client should close with 1009 (Message Too Big)')
})

test('Oversized frame is rejected with the default configuration before its payload arrives', async (t) => {
  let messageReceived = false

  const { server, closeCode } = await createRawServer(t, (socket) => {
    setTimeout(() => {
      // Announce a 200 MB compressed frame but never send its payload: the
      // client must not wait for (and buffer) it.
      socket.write(createWebSocketFrameHeader({ opcode: 2, rsv1: true, length: 200 * 1024 * 1024 }))
    }, 100)
  })

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

  client.addEventListener('message', () => {
    messageReceived = true
  })

  const closed = await raceTimeout(once(client, 'close'), 5000)

  assert.ok(closed, 'Connection should be closed after exceeding the default limit')
  assert.strictEqual(messageReceived, false)
  assert.strictEqual(client.readyState, WebSocket.CLOSED)
  assert.strictEqual(await closeCode, 1009, 'Client should close with 1009 (Message Too Big)')
})

test('Default limit applies when the dispatcher does not expose webSocketOptions', async (t) => {
  let messageReceived = false

  const { server, closeCode } = await createRawServer(t, (socket) => {
    setTimeout(() => {
      socket.write(createWebSocketFrameHeader({ opcode: 2, rsv1: true, length: 200 * 1024 * 1024 }))
    }, 100)
  })

  const agent = new Agent()
  t.after(() => agent.close())

  const dispatcher = new ForwardingDispatcher(agent)
  assert.strictEqual(dispatcher.webSocketOptions, undefined)

  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { dispatcher })

  client.addEventListener('message', () => {
    messageReceived = true
  })

  const closed = await raceTimeout(once(client, 'close'), 5000)

  assert.ok(closed, 'Connection should be closed after exceeding the default limit')
  assert.strictEqual(messageReceived, false)
  assert.strictEqual(await closeCode, 1009, 'Client should close with 1009 (Message Too Big)')
})
