'use strict'

const assert = require('node:assert')
const { describe, test, after } = require('node:test')
const { once } = require('node:events')
const http = require('node:http')
const crypto = require('node:crypto')
const zlib = require('node:zlib')
const { WebSocket } = require('../..')
const { isValidClientWindowBits } = require('../../lib/web/websocket/util')

/**
 * Creates a minimal WebSocket server that responds with a custom
 * server_max_window_bits value and sends a compressed frame.
 */
function createMaliciousServer (windowBitsValue) {
  const server = http.createServer()
  const sockets = new Set()

  server.on('upgrade', (req, socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))

    const key = req.headers['sec-websocket-key']
    const accept = crypto
      .createHash('sha1')
      .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      .digest('base64')

    const headers = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${accept}`,
      `Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=${windowBitsValue}`,
      '', ''
    ]

    socket.write(headers.join('\r\n'))

    // Send a compressed frame to trigger decompression
    setTimeout(() => {
      if (!socket.destroyed) {
        const payload = zlib.deflateRawSync(Buffer.from('Hello'))
        // Remove trailing 00 00 ff ff if present
        const trimmed = payload.subarray(0, payload.length - 4)
        const frame = makeWsFrame({ opcode: 2, rsv1: true, payload: trimmed })
        socket.write(frame)
      }
    }, 50)
  })

  // Override close to also destroy sockets
  const originalClose = server.close.bind(server)
  server.close = (cb) => {
    for (const socket of sockets) {
      socket.destroy()
    }
    sockets.clear()
    originalClose(cb)
  }

  return server
}

/**
 * Creates a WebSocket frame (server-to-client, unmasked)
 */
function makeWsFrame ({ opcode, rsv1, payload }) {
  const fin = 1
  const b0 = (fin << 7) | ((rsv1 ? 1 : 0) << 6) | (opcode & 0x0f)
  const len = payload.length

  let header
  if (len <= 125) {
    header = Buffer.from([b0, len])
  } else if (len <= 0xffff) {
    header = Buffer.alloc(4)
    header[0] = b0
    header[1] = 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = b0
    header[1] = 127
    header.writeUInt32BE(0, 2)
    header.writeUInt32BE(len, 6)
  }

  return Buffer.concat([header, payload])
}

/**
 * Invalid server_max_window_bits triggers closeWebSocketConnection (1007).
 * The TCP socket may stay open if the peer ignores the close frame, so `close`
 * may never fire; readyState still becomes CLOSING (2).
 */
async function afterOpenWaitUntilClosing (client, timeoutMs = 10000) {
  await once(client, 'open')
  const deadline = Date.now() + timeoutMs
  while (client.readyState < WebSocket.CLOSING) {
    if (Date.now() > deadline) {
      throw new Error('Timed out waiting for WebSocket to enter CLOSING')
    }
    await new Promise(resolve => setTimeout(resolve, 5))
  }
}

describe('isValidClientWindowBits', () => {
  test('rejects empty string', (t) => {
    assert.strictEqual(isValidClientWindowBits(''), false)
  })

  test('rejects values below 8', (t) => {
    assert.strictEqual(isValidClientWindowBits('0'), false)
    assert.strictEqual(isValidClientWindowBits('1'), false)
    assert.strictEqual(isValidClientWindowBits('7'), false)
  })

  test('accepts values 8-15', (t) => {
    for (let i = 8; i <= 15; i++) {
      assert.strictEqual(isValidClientWindowBits(String(i)), true, `${i} should be valid`)
    }
  })

  test('rejects values above 15', (t) => {
    assert.strictEqual(isValidClientWindowBits('16'), false)
    assert.strictEqual(isValidClientWindowBits('100'), false)
    assert.strictEqual(isValidClientWindowBits('1000'), false)
    assert.strictEqual(isValidClientWindowBits('999999'), false)
  })

  test('rejects non-numeric values', (t) => {
    assert.strictEqual(isValidClientWindowBits('abc'), false)
    assert.strictEqual(isValidClientWindowBits('12a'), false)
    assert.strictEqual(isValidClientWindowBits('-1'), false)
    assert.strictEqual(isValidClientWindowBits('8.5'), false)
  })
})

describe('permessage-deflate server_max_window_bits', () => {
  test('server_max_window_bits=8 works correctly', async (t) => {
    const server = createMaliciousServer('8')
    await new Promise(resolve => server.listen(0, resolve))
    after(() => server.close())

    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

    const [event] = await once(client, 'message')
    assert.ok(event.data)
    client.close()
  })

  test('server_max_window_bits=15 works correctly', async (t) => {
    const server = createMaliciousServer('15')
    await new Promise(resolve => server.listen(0, resolve))
    after(() => server.close())

    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

    const [event] = await once(client, 'message')
    assert.ok(event.data)
    client.close()
  })

  test('server_max_window_bits=0 is rejected gracefully', async (t) => {
    const server = createMaliciousServer('0')
    await new Promise(resolve => server.listen(0, resolve))
    after(() => server.close())

    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

    await afterOpenWaitUntilClosing(client)
    assert.ok(client.readyState === WebSocket.CLOSING || client.readyState === WebSocket.CLOSED)
  })

  test('server_max_window_bits=7 is rejected gracefully', async (t) => {
    const server = createMaliciousServer('7')
    await new Promise(resolve => server.listen(0, resolve))
    after(() => server.close())

    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

    await afterOpenWaitUntilClosing(client)
    assert.ok(client.readyState === WebSocket.CLOSING || client.readyState === WebSocket.CLOSED)
  })

  test('server_max_window_bits=16 is rejected gracefully', async (t) => {
    const server = createMaliciousServer('16')
    await new Promise(resolve => server.listen(0, resolve))
    after(() => server.close())

    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

    await afterOpenWaitUntilClosing(client)
    assert.ok(client.readyState === WebSocket.CLOSING || client.readyState === WebSocket.CLOSED)
  })

  test('server_max_window_bits=1000 is rejected gracefully (PoC attack)', async (t) => {
    const server = createMaliciousServer('1000')
    await new Promise(resolve => server.listen(0, resolve))
    after(() => server.close())

    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

    await afterOpenWaitUntilClosing(client)
    assert.ok(client.readyState === WebSocket.CLOSING || client.readyState === WebSocket.CLOSED)
  })

  test('no uncaught exception with invalid windowBits', async (t) => {
    let uncaughtException = false

    const handler = () => {
      uncaughtException = true
    }
    process.on('uncaughtException', handler)

    const server = createMaliciousServer('1000')
    await new Promise(resolve => server.listen(0, resolve))
    after(() => {
      server.close()
      process.off('uncaughtException', handler)
    })

    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

    await afterOpenWaitUntilClosing(client)

    assert.strictEqual(uncaughtException, false, 'No uncaught exception should occur')
  })

  test('invalid windowBits closes connection without crashing process', async (t) => {
    const server = createMaliciousServer('999999')
    await new Promise(resolve => server.listen(0, resolve))
    after(() => server.close())

    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`)

    await afterOpenWaitUntilClosing(client)
    assert.ok(client.readyState === WebSocket.CLOSING || client.readyState === WebSocket.CLOSED)
  })
})
