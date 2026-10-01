'use strict'

const { test } = require('node:test')
const assert = require('node:assert')
const { once } = require('node:events')
const { deflateRawSync, constants: { Z_SYNC_FLUSH } } = require('node:zlib')
const { setTimeout: sleep } = require('node:timers/promises')
const { ByteParser } = require('../../lib/web/websocket/receiver')
const { PerMessageDeflate } = require('../../lib/web/websocket/permessage-deflate')
const { states, sentCloseFrameState } = require('../../lib/web/websocket/constants')
const {
  kController,
  kResponse,
  kReadyState,
  kSentClose,
  kBinaryType,
  kWebSocketURL
} = require('../../lib/web/websocket/symbols')
const { MessageSizeExceededError } = require('../../lib/core/errors')

const invalidFrame = Buffer.from([0x82, 0x7F, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])

/**
 * Creates a minimal object that ByteParser can drive like an open WebSocket.
 */
function createOpenWebSocket () {
  const calls = {
    abort: 0,
    destroy: 0,
    written: [],
    messages: [],
    errors: []
  }

  const ws = new EventTarget()
  ws[kReadyState] = states.OPEN
  ws[kSentClose] = sentCloseFrameState.NOT_SENT
  ws[kBinaryType] = 'arraybuffer'
  ws[kWebSocketURL] = new URL('ws://localhost')
  ws[kController] = {
    abort: () => {
      calls.abort += 1
    }
  }
  ws[kResponse] = {
    socket: {
      destroyed: false,
      write (data) {
        calls.written.push(Buffer.from(data))
        return true
      },
      destroy () {
        this.destroyed = true
        calls.destroy += 1
      }
    }
  }

  ws.addEventListener('message', (event) => {
    calls.messages.push(event.data)
  })

  ws.addEventListener('error', (event) => {
    calls.errors.push(event.message)
  })

  return { ws, calls }
}

/**
 * Decodes a (masked) close frame written by the client.
 * @param {Buffer} frame
 */
function decodeCloseFrame (frame) {
  assert.strictEqual(frame[0], 0x88, 'expected a close frame')
  const length = frame[1] & 0x7F
  const mask = frame.subarray(2, 6)
  const payload = Buffer.from(frame.subarray(6, 6 + length))

  for (let i = 0; i < payload.length; i++) {
    payload[i] ^= mask[i % 4]
  }

  return { code: payload.readUInt16BE(0), reason: payload.subarray(2).toString('utf8') }
}

function createFrameHeader ({ fin = true, rsv1 = false, opcode, length }) {
  const first = (fin ? 0x80 : 0x00) | (rsv1 ? 0x40 : 0x00) | opcode

  if (length > 0xFFFF) {
    const header = Buffer.alloc(10)
    header[0] = first
    header[1] = 127
    header.writeUInt32BE(0, 2)
    header.writeUInt32BE(length, 6)
    return header
  } else if (length > 125) {
    const header = Buffer.alloc(4)
    header[0] = first
    header[1] = 126
    header.writeUInt16BE(length, 2)
    return header
  }

  return Buffer.from([first, length])
}

function createFrame (options) {
  return Buffer.concat([createFrameHeader({ ...options, length: options.payload.length }), options.payload])
}

async function raceTimeout (promise, ms) {
  const ac = new AbortController()

  try {
    return await Promise.race([promise, sleep(ms, null, { signal: ac.signal })])
  } finally {
    ac.abort()
  }
}

function assertFailedWith1009 (calls, reason) {
  assert.strictEqual(calls.messages.length, 0, 'no message must be dispatched')
  assert.strictEqual(calls.written.length, 1, 'a close frame must be sent')
  const close = decodeCloseFrame(calls.written[0])
  assert.strictEqual(close.code, 1009)
  assert.strictEqual(close.reason, reason)
  assert.strictEqual(calls.abort, 1)
  assert.strictEqual(calls.destroy, 1, 'the socket must be destroyed')
  assert.deepStrictEqual(calls.errors, [reason])
}

test('ByteParser rejects 64-bit payload lengths with a non-zero upper word', (t) => {
  const calls = {
    abort: 0,
    destroy: 0
  }

  const ws = new EventTarget()
  ws[kController] = {
    abort: () => {
      calls.abort += 1
    }
  }
  ws[kResponse] = {
    socket: {
      destroyed: false,
      destroy: () => {
        calls.destroy += 1
      }
    }
  }

  const parser = new ByteParser(ws)

  parser.write(invalidFrame)

  return new Promise((resolve) => {
    setImmediate(() => {
      assert.strictEqual(calls.abort, 1)
      assert.strictEqual(calls.destroy, 1)
      parser.destroy()
      resolve()
    })
  })
})

test('ByteParser rejects declared payload lengths over maxPayloadSize before buffering the body', async (t) => {
  const cases = [
    { name: '7-bit', limit: 100, length: 101 },
    { name: '16-bit', limit: 1024, length: 2048 },
    { name: '64-bit', limit: 1024 * 1024, length: 200 * 1024 * 1024 }
  ]

  for (const { name, limit, length } of cases) {
    for (const rsv1 of [false, true]) {
      const { ws, calls } = createOpenWebSocket()
      const extensions = rsv1 ? new Map([['permessage-deflate', '']]) : null
      const parser = new ByteParser(ws, extensions, { maxPayloadSize: limit })

      // Only the frame header is sent: the parser must fail the connection
      // without waiting for (and buffering) the announced payload.
      parser.write(createFrameHeader({ opcode: 0x2, rsv1, length }))

      await new Promise((resolve) => setImmediate(resolve))

      assertFailedWith1009(calls, 'Payload size exceeds maximum allowed size')
      assert.strictEqual(ws[kReadyState], states.CLOSING, `${name} (rsv1=${rsv1})`)
      parser.destroy()
    }
  }
})

test('ByteParser rejects fragmented uncompressed messages whose total size exceeds maxPayloadSize', async (t) => {
  const { ws, calls } = createOpenWebSocket()
  const parser = new ByteParser(ws, null, { maxPayloadSize: 1024 })

  const chunk = Buffer.alloc(512, 0x41)
  parser.write(createFrame({ fin: false, opcode: 0x2, payload: chunk }))
  parser.write(createFrame({ fin: false, opcode: 0x0, payload: chunk }))
  parser.write(createFrame({ fin: true, opcode: 0x0, payload: chunk }))

  await new Promise((resolve) => setImmediate(resolve))

  // The cumulative size is checked as soon as the last frame's length is
  // known, before its body is buffered.
  assertFailedWith1009(calls, 'Payload size exceeds maximum allowed size')
  parser.destroy()
})

test('ByteParser fails the connection with 1008 once a message exceeds maxFragments', async (t) => {
  const { ws, calls } = createOpenWebSocket()
  const parser = new ByteParser(ws, null, { maxFragments: 3 })

  // A message that is never terminated: without a limit every fragment
  // would be buffered for as long as the peer keeps sending.
  const chunk = Buffer.from('a')
  parser.write(createFrame({ fin: false, opcode: 0x2, payload: chunk }))
  parser.write(createFrame({ fin: false, opcode: 0x0, payload: chunk }))
  parser.write(createFrame({ fin: false, opcode: 0x0, payload: chunk }))
  parser.write(createFrame({ fin: false, opcode: 0x0, payload: chunk }))

  await new Promise((resolve) => setImmediate(resolve))

  assert.strictEqual(calls.messages.length, 0, 'no message must be dispatched')
  assert.strictEqual(calls.written.length, 1, 'a close frame must be sent')
  const close = decodeCloseFrame(calls.written[0])
  assert.strictEqual(close.code, 1008)
  assert.strictEqual(close.reason, 'Too many message fragments')
  assert.strictEqual(calls.abort, 1)
  assert.strictEqual(calls.destroy, 1, 'the socket must be destroyed')
  assert.deepStrictEqual(calls.errors, ['Too many message fragments'])
  parser.destroy()
})

test('ByteParser applies maxFragments per message and ignores interleaved control frames', async (t) => {
  const { ws, calls } = createOpenWebSocket()
  const parser = new ByteParser(ws, null, { maxFragments: 3 })

  for (let i = 0; i < 3; i++) {
    parser.write(createFrame({ fin: false, opcode: 0x2, payload: Buffer.from('a') }))
    parser.write(createFrame({ opcode: 0x9, payload: Buffer.from('ping') }))
    parser.write(createFrame({ fin: false, opcode: 0x0, payload: Buffer.from('b') }))
    parser.write(createFrame({ fin: true, opcode: 0x0, payload: Buffer.from('c') }))
  }

  await new Promise((resolve) => setImmediate(resolve))

  assert.strictEqual(calls.messages.length, 3)
  for (const message of calls.messages) {
    assert.strictEqual(Buffer.from(message).toString(), 'abc')
  }
  assert.strictEqual(calls.abort, 0)
  assert.strictEqual(calls.destroy, 0)
  assert.deepStrictEqual(calls.errors, [])
  parser.destroy()
})

test('ByteParser rejects a permessage-deflate decompression bomb', async (t) => {
  const { ws, calls } = createOpenWebSocket()
  const extensions = new Map([['permessage-deflate', '']])
  const parser = new ByteParser(ws, extensions, { maxPayloadSize: 64 * 1024 })

  // ~10 KB on the wire, 16 MB once inflated.
  const bomb = deflateRawSync(Buffer.alloc(16 * 1024 * 1024))
  assert.ok(bomb.length < 64 * 1024)

  const errored = once(ws, 'error')
  parser.write(createFrame({ opcode: 0x2, rsv1: true, payload: bomb }))

  const result = await raceTimeout(errored, 5000)
  assert.ok(result, 'the connection must be failed')

  assertFailedWith1009(calls, new MessageSizeExceededError().message)
  parser.destroy()
})

test('ByteParser rejects fragmented compressed messages whose total inflated size exceeds maxPayloadSize', async (t) => {
  const { ws, calls } = createOpenWebSocket()
  const extensions = new Map([['permessage-deflate', '']])
  const parser = new ByteParser(ws, extensions, { maxPayloadSize: 64 * 1024 })

  // Each fragment inflates to 48 KB (under the limit), the message to 96 KB.
  const first = deflateRawSync(Buffer.alloc(48 * 1024, 0x41), { finishFlush: Z_SYNC_FLUSH })
  const last = deflateRawSync(Buffer.alloc(48 * 1024, 0x42), { finishFlush: Z_SYNC_FLUSH }).subarray(0, -4)

  const errored = once(ws, 'error')
  parser.write(createFrame({ fin: false, rsv1: true, opcode: 0x2, payload: first }))
  parser.write(createFrame({ fin: true, opcode: 0x0, payload: last }))

  const result = await raceTimeout(errored, 5000)
  assert.ok(result, 'the connection must be failed')

  assertFailedWith1009(calls, new MessageSizeExceededError().message)
  parser.destroy()
})

test('ByteParser delivers fragmented compressed messages under maxPayloadSize', async (t) => {
  const { ws, calls } = createOpenWebSocket()
  const extensions = new Map([['permessage-deflate', '']])
  const parser = new ByteParser(ws, extensions, { maxPayloadSize: 96 * 1024 })

  const first = deflateRawSync(Buffer.alloc(48 * 1024, 0x41), { finishFlush: Z_SYNC_FLUSH })
  const last = deflateRawSync(Buffer.alloc(48 * 1024, 0x42), { finishFlush: Z_SYNC_FLUSH }).subarray(0, -4)

  const received = once(ws, 'message')
  parser.write(createFrame({ fin: false, rsv1: true, opcode: 0x2, payload: first }))
  parser.write(createFrame({ fin: true, opcode: 0x0, payload: last }))

  const result = await raceTimeout(received, 5000)
  assert.ok(result, 'the message must be delivered')

  assert.strictEqual(calls.messages.length, 1)
  assert.deepStrictEqual(
    Buffer.from(calls.messages[0]),
    Buffer.concat([Buffer.alloc(48 * 1024, 0x41), Buffer.alloc(48 * 1024, 0x42)])
  )
  assert.strictEqual(calls.written.length, 0)
  assert.strictEqual(calls.destroy, 0)
  parser.destroy()
})

test('PerMessageDeflate stops inflating once maxPayloadSize is exceeded', async (t) => {
  const pmd = new PerMessageDeflate(new Map([['permessage-deflate', '']]), { maxPayloadSize: 1024 * 1024 })
  const bomb = deflateRawSync(Buffer.alloc(64 * 1024 * 1024))
  const results = []

  pmd.decompress(bomb, true, (error, data) => {
    results.push({ error, data })
  })

  // Give zlib ample time to (wrongly) keep producing output or call back twice.
  await sleep(200)

  assert.strictEqual(results.length, 1)
  assert.ok(results[0].error instanceof MessageSizeExceededError)
  assert.strictEqual(results[0].error.code, 'UND_ERR_WS_MESSAGE_SIZE_EXCEEDED')
  assert.strictEqual(results[0].data, undefined)
})

test('PerMessageDeflate inflates messages at exactly maxPayloadSize', async (t) => {
  const limit = 256 * 1024
  const pmd = new PerMessageDeflate(new Map([['permessage-deflate', '']]), { maxPayloadSize: limit })
  const payload = deflateRawSync(Buffer.alloc(limit, 0x41), { finishFlush: Z_SYNC_FLUSH }).subarray(0, -4)

  const [error, data] = await new Promise((resolve) => {
    pmd.decompress(payload, true, (error, data) => resolve([error, data]))
  })

  assert.strictEqual(error, null)
  assert.strictEqual(data.length, limit)
})
