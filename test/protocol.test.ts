import { expect, test } from 'bun:test'
import { createOuraProtocol, OuraProtocolError, type Output } from '../bindings/protocol'
import capture from './ring5-capture.json'
const bytes = (hex: string) => Uint8Array.from(hex.match(/../g) || [], item => Number.parseInt(item, 16))
const key = Uint8Array.from({ length: 16 }, (_, index) => index)
const nonce = Uint8Array.from([0x2f, 16, 0x2c, ...key.slice(0, 15)])
async function ready() {
  const protocol = await createOuraProtocol()
  expect(protocol.begin(key, 0)).toEqual({ kind: 'write', bytes: bytes('2f012b') })
  const answer = [...protocol.receive(nonce, 1)]
  expect(answer).toEqual([{ kind: 'write', bytes: bytes('2f112db61e6af8da7260d2214369b951bf8963'), sensitive: true }])
  expect([...protocol.receive(bytes('2f022e00'), 2)]).toEqual([{ kind: 'ready' }])
  return protocol
}
test('native WASM decodes the captured Ring 5 bundle against the independent reference oracle', async () => {
  const protocol = await ready()
  protocol.sync('extended', 0, 4096, 3)
  const seen: string[] = []
  try {
    for (const output of protocol.receive(bytes(capture.notification), 4)) {
      expect(output.kind).toBe('event')
      if (output.kind !== 'event') continue
      const event = output.event
      const expected = bytes(capture.events[seen.length]!)
      expect(event.tag).toBe(expected[0]!)
      expect(event.timestampDs).toBe(new DataView(expected.buffer).getUint32(2, true))
      expect(event.body).toEqual(expected.slice(6))
      // Decode while the next events still borrow notification memory. It must
      // not overwrite the input stream or the bundle's unread records.
      try { protocol.decode(event) } catch (error) { expect(error).toBeInstanceOf(OuraProtocolError); expect((error as OuraProtocolError).code).toBe(-3) }
      seen.push(Buffer.from(event.body).toString('hex'))
      protocol.accept()
    }
    expect(seen).toHaveLength(capture.events.length)
    expect(() => protocol.commit()).toThrow()
    const summary = bytes('2f0a420a0000000000000000')
    const output = [...protocol.receive(summary, 5)][0]!
    expect(output.kind).toBe('batch')
    if (output.kind === 'batch') expect(protocol.commit()).toBe(output.nextCursor)
  }
  finally { protocol.close() }
})
test('legacy coalesced packets remain intact while readings are decoded', async () => {
  const protocol = await ready()
  protocol.sync('legacy', 100, 255, 3)
  const notification = bytes('5d086e0000003c283e2d6f0878000000016263ff1106020000000000')
  const outputs: Output[] = []
  for (const output of protocol.receive(notification, 4)) {
    outputs.push(output)
    if (output.kind === 'event') {
      const readings = protocol.decode(output.event)
      if (output.event.tag === 0x5d) expect(readings.map(sample => sample.value)).toEqual([60, 40, 62, 45])
      if (output.event.tag === 0x6f) expect(readings.map(sample => sample.value)).toEqual([98, 99])
      protocol.accept()
    }
  }
  expect(outputs.map(output => output.kind)).toEqual(['event', 'event', 'batch'])
  expect(protocol.commit()).toBe(121)
  protocol.close()
})
test('failed authentication includes the result code and never exposes the pairing key', async () => {
  const protocol = await createOuraProtocol()
  protocol.begin(key, 0)
  ;[...protocol.receive(nonce, 1)]
  try { [...protocol.receive(bytes('2f022e03'), 2)]; throw new Error('accepted invalid pairing') }
  catch (error) { expect(error).toBeInstanceOf(OuraProtocolError); expect((error as OuraProtocolError).authResult).toBe(3); expect(String(error)).not.toContain(Buffer.from(key).toString('hex')) }
  finally { protocol.close() }
})
test('partial envelopes, missing summary and event count mismatch cannot commit', async () => {
  const protocol = await ready()
  protocol.sync('extended', 0, 4096, 3)
  expect([...protocol.receive(bytes('2f04430600aa'), 4)]).toEqual([])
  expect(() => [...protocol.receive(bytes('2f0a42000000000000000000'), 5)]).toThrow('Incomplete Oura history')
  expect(() => protocol.commit()).toThrow()
  protocol.close()
})
test('instances are independent and reject reads after close', async () => {
  const first = await ready(), second = await ready()
  first.close()
  expect(() => [...first.receive(bytes('2f022e00'), 4)]).toThrow()
  expect(second.request(2)).toEqual(bytes('0c00'))
  second.close()
})
test('the captured bundle survives every possible envelope split boundary', async () => {
  const data = bytes(capture.notification).slice(3)
  for (let split = 0; split <= data.length; split++) {
    const protocol = await ready()
    protocol.sync('extended', 0, 4096, 3)
    let seen = 0
    try {
      for (const part of [data.slice(0, split), data.slice(split)]) {
        const notification = Uint8Array.from([0x2f, part.length + 1, 0x43, ...part])
        for (const output of protocol.receive(notification, 4)) {
          expect(output.kind).toBe('event')
          if (output.kind !== 'event') continue
          const expected = bytes(capture.events[seen++]!)
          expect(output.event.tag).toBe(expected[0]!)
          expect(output.event.timestampDs).toBe(new DataView(expected.buffer).getUint32(2, true))
          expect(output.event.body).toEqual(expected.slice(6))
          protocol.accept()
        }
      }
      expect(seen).toBe(10)
      expect([...protocol.receive(bytes('2f0a420a0000000000000000'), 5)][0]!.kind).toBe('batch')
      protocol.commit()
    }
    finally { protocol.close() }
  }
})
