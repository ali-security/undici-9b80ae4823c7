'use strict'

const assert = require('node:assert')
const { once } = require('node:events')
const { createServer } = require('node:net')
const { test } = require('node:test')
const { Client, errors } = require('..')

function readBody (body) {
  return new Promise((resolve, reject) => {
    let data = ''
    body.setEncoding('latin1')
    body.on('data', chunk => { data += chunk })
    body.on('end', () => resolve(data))
    body.on('error', reject)
  })
}

test('should not reuse an idle socket with buffered unsolicited response bytes', async (t) => {
  let responses = 0

  const server = createServer((socket) => {
    socket.on('data', () => {
      if (responses++ === 0) {
        socket.write(
          'HTTP/1.1 200 OK\r\n' +
          'Connection: keep-alive\r\n' +
          'Keep-Alive: timeout=300\r\n' +
          'Content-Length: 9\r\n' +
          '\r\n' +
          '/request1' +
          'HTTP/1.1 200 OK\r\n' +
          'Poison-Free-Socket: true\r\n' +
          'Connection: keep-alive\r\n' +
          'Keep-Alive: timeout=300\r\n' +
          'Content-Length: 0\r\n' +
          '\r\n'
        )
      } else {
        socket.end(
          'HTTP/1.1 200 OK\r\n' +
          'Connection: close\r\n' +
          'Content-Length: 9\r\n' +
          '\r\n' +
          '/request2'
        )
      }
    })
  })
  t.after(() => server.close())

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')

  const client = new Client(`http://127.0.0.1:${server.address().port}`, {
    keepAliveTimeout: 300e3
  })
  t.after(() => client.close())

  const disconnected = once(client, 'disconnect')

  const response1 = await client.request({ path: '/request1', method: 'GET' })
  assert.strictEqual(await readBody(response1.body), '/request1')

  await disconnected

  const response2 = await client.request({ path: '/request2', method: 'GET' })
  assert.strictEqual(response2.headers['poison-free-socket'], undefined)
  assert.strictEqual(await readBody(response2.body), '/request2')
})

test('should not attribute unsolicited response bytes to a queued request', async (t) => {
  let connections = 0

  const server = createServer((socket) => {
    const connection = ++connections
    let requests = 0

    socket.on('error', () => {})
    socket.on('data', () => {
      if (connection === 1 && requests++ === 0) {
        // Response to request 1 immediately followed, in the same write, by a
        // response nobody asked for. Request 2 is queued on the client but has
        // not been written yet (pipelining: 1).
        socket.write(
          'HTTP/1.1 200 OK\r\n' +
          'Connection: keep-alive\r\n' +
          'Keep-Alive: timeout=300\r\n' +
          'Content-Length: 9\r\n' +
          '\r\n' +
          '/request1' +
          'HTTP/1.1 200 OK\r\n' +
          'Poison-Free-Socket: true\r\n' +
          'Connection: keep-alive\r\n' +
          'Keep-Alive: timeout=300\r\n' +
          'Content-Length: 0\r\n' +
          '\r\n'
        )
      } else {
        socket.end(
          'HTTP/1.1 200 OK\r\n' +
          'Connection: close\r\n' +
          'Content-Length: 9\r\n' +
          '\r\n' +
          '/request2'
        )
      }
    })
  })
  t.after(() => server.close())

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')

  const client = new Client(`http://127.0.0.1:${server.address().port}`, {
    keepAliveTimeout: 300e3,
    pipelining: 1
  })
  t.after(() => client.close())

  const disconnects = []
  client.on('disconnect', (origin, targets, err) => {
    disconnects.push(err)
  })

  const request1 = client.request({ path: '/request1', method: 'GET' })
  const request2 = client.request({ path: '/request2', method: 'GET' })

  const response1 = await request1
  assert.strictEqual(await readBody(response1.body), '/request1')

  const response2 = await request2
  assert.strictEqual(response2.headers['poison-free-socket'], undefined)
  assert.strictEqual(await readBody(response2.body), '/request2')

  assert.strictEqual(connections, 2)
  assert.ok(disconnects.length >= 1)
  assert.ok(disconnects[0] instanceof errors.SocketError)
  assert.strictEqual(disconnects[0].message, 'bad response')
})

test('should validate an idle keep-alive socket before writing the next request', async (t) => {
  const serverSockets = []

  const server = createServer((socket) => {
    const connection = serverSockets.push(socket)

    socket.on('error', () => {})
    socket.on('data', (chunk) => {
      const path = chunk.toString('latin1').split(' ')[1]
      socket.write(
        'HTTP/1.1 200 OK\r\n' +
        'Connection: keep-alive\r\n' +
        'Keep-Alive: timeout=300\r\n' +
        `X-Connection: ${connection}\r\n` +
        `Content-Length: ${path.length}\r\n` +
        '\r\n' +
        path
      )
    })
  })
  t.after(() => {
    for (const socket of serverSockets) {
      socket.destroy()
    }
    server.close()
  })

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')

  const client = new Client(`http://127.0.0.1:${server.address().port}`, {
    keepAliveTimeout: 300e3
  })
  t.after(() => client.destroy())

  const disconnects = []
  client.on('disconnect', (origin, targets, err) => {
    disconnects.push(err)
  })

  const response1 = await client.request({ path: '/request1', method: 'GET' })
  assert.strictEqual(await readBody(response1.body), '/request1')
  assert.strictEqual(response1.headers['x-connection'], '1')
  assert.strictEqual(serverSockets.length, 1)

  // The keep-alive socket is now idle. Make an unsolicited response reach the
  // client's kernel buffer without letting the event loop read it yet, then
  // reuse the socket for the next request from the same tick.
  const response2 = await new Promise((resolve, reject) => {
    setTimeout(() => {
      serverSockets[0].write(
        'HTTP/1.1 200 OK\r\n' +
        'Poison-Free-Socket: true\r\n' +
        'Connection: keep-alive\r\n' +
        'Keep-Alive: timeout=300\r\n' +
        'Content-Length: 0\r\n' +
        '\r\n'
      )
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100)
      client.request({ path: '/request2', method: 'GET' }).then(resolve, reject)
    }, 50)
  })

  assert.strictEqual(response2.headers['poison-free-socket'], undefined)
  assert.strictEqual(response2.headers['x-connection'], '2')
  assert.strictEqual(await readBody(response2.body), '/request2')

  assert.strictEqual(disconnects.length, 1)
  assert.ok(disconnects[0] instanceof errors.SocketError)
  assert.strictEqual(disconnects[0].message, 'bad response')
})
