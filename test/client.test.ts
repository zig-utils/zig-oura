import { expect, test } from 'bun:test'
import { OuraBleClient, OuraTransportError, type OuraTransport } from '../bindings/client'
import { createOuraProtocol, type RingEvent } from '../bindings/protocol'
const key = Uint8Array.from({ length: 16 }, (_, index) => index)
const hex = (value: Uint8Array) => Buffer.from(value).toString('hex')
const bytes = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'))
const packet = (tag: number, payload: number[]) => Uint8Array.from([tag, payload.length, ...payload])
class ScriptedTransport implements OuraTransport {
  queue: Uint8Array[] = []
  writes: Uint8Array[] = []
  closed = false
  constructor(readonly options: { ring5?: boolean, failStorage?: boolean, missingSummary?: boolean, endless?: boolean } = {}) {}
  async write(value: Uint8Array) {
    if (this.closed) throw new OuraTransportError('disconnected')
    this.writes.push(value.slice())
    const request = hex(value)
    if (request === '2f012b') this.queue.push(packet(0x2f, [0x2c, ...key.slice(0, 15)]))
    else if (request.startsWith('2f112d')) this.queue.push(bytes('2f022e00'))
    else if (request === '1803180010') this.queue.push(packet(0x19, [0, ...new TextEncoder().encode(this.options.ring5 ? 'ORE_05' : 'BLB_03')]))
    else if (request.startsWith('2f0201')) this.queue.push(bytes('2f020200'))
    else if (request === '160102') this.queue.push(bytes('170100'))
    else if (request.startsWith('1803')) this.queue.push(bytes('190100'))
    else if (request.startsWith('2f0220')) this.queue.push(bytes('2f022100'))
    else if (request === '2f020301') this.queue.push(bytes('2f020400'))
    else if (request === '280100') this.queue.push(bytes('290100'))
    else if (request.startsWith('2f0c41')) this.queue.push(bytes('2f0100')) // explicit unsupported extended API
    else if (request.startsWith('1009')) {
      const cursor = new DataView(value.buffer, value.byteOffset).getUint32(2, true)
      if (cursor <= 110 || this.options.endless) {
        const timestamp = this.options.endless ? cursor + 1 : 110
        const body = packet(0x5d, [timestamp & 255, (timestamp >>> 8) & 255, (timestamp >>> 16) & 255, timestamp >>> 24, 60, 40])
        const summary = bytes('1106010000000000')
        this.queue.push(this.options.missingSummary ? body : Uint8Array.from([...body, ...summary]))
      }
      else this.queue.push(bytes('1106000000000000'))
    }
    else throw new Error(`Unexpected test request ${request}`)
  }
  async read() {
    if (this.closed) throw new OuraTransportError('disconnected')
    const next = this.queue.shift()
    if (!next) throw new OuraTransportError('timeout')
    return next
  }
  async close() { this.closed = true; this.queue = [] }
}
async function client(options: ConstructorParameters<typeof ScriptedTransport>[0] = {}) {
  const transport = new ScriptedTransport(options)
  const protocol = await createOuraProtocol()
  const instance = new OuraBleClient(transport, protocol, { now: () => 10 })
  await instance.open(key)
  return { transport, protocol, instance }
}
test('negotiates legacy only on explicit rejection and durably stores each event before its checkpoint', async () => {
  const { transport, protocol, instance } = await client()
  const stored: RingEvent[] = []
  let checkpoint = 0
  const result = await instance.sync({ cursor: 0, onEvent: async event => {
    expect(checkpoint).toBe(0)
    expect(protocol.decode(event).map(sample => sample.value)).toEqual([60, 40])
    stored.push(event)
  }, onBatch: async batch => { expect(stored).toHaveLength(1); checkpoint = batch.nextCursor } })
  expect(result).toEqual({ nextCursor: 111, events: 1, mode: 'legacy' })
  expect(checkpoint).toBe(111)
  expect(transport.writes.filter(value => hex(value).startsWith('2f0c41'))).toHaveLength(1)
  expect(transport.writes.some(value => value[0] === 0x1a || value[0] === 0x24 || value[0] === 0x12)).toBe(false)
  await instance.close()
  expect(transport.closed).toBe(true)
})
test('Ring 5 app stream registrations precede history fetches', async () => {
  const { transport, instance } = await client({ ring5: true })
  const sent = transport.writes.map(hex)
  expect(sent).toContain('160102')
  expect(sent).toContain('1803140010')
  expect(sent).toContain('1803280009')
  expect(sent).toContain('2f022010')
  await instance.close()
})
test('failed storage never advances the checkpoint and closes the transport', async () => {
  const { transport, instance } = await client()
  let checkpointed = false
  await expect(instance.sync({ cursor: 0, mode: 'legacy', onEvent: async () => { throw new Error('disk full') }, onBatch: async () => { checkpointed = true } })).rejects.toThrow('disk full')
  expect(checkpointed).toBe(false)
  expect(transport.closed).toBe(true)
})
test('missing summary closes the connection without checkpointing a partial batch', async () => {
  const { transport, instance } = await client({ missingSummary: true })
  let checkpointed = false
  await expect(instance.sync({ cursor: 0, mode: 'legacy', onEvent: async () => {}, onBatch: async () => { checkpointed = true } })).rejects.toThrow('timeout')
  expect(checkpointed).toBe(false)
  expect(transport.closed).toBe(true)
})
test('explicit extended-only mode fails rather than changing the requested protocol', async () => {
  const { transport, instance } = await client()
  await expect(instance.sync({ cursor: 0, mode: 'extended', onEvent: async () => {}, onBatch: async () => {} })).rejects.toThrow('Unsupported Oura operation')
  expect(transport.writes.some(value => value[0] === 0x10)).toBe(false)
})
test('a bounded small tail ends even when the ring keeps creating new events', async () => {
  const { instance } = await client({ endless: true })
  const cursors: number[] = []
  const result = await instance.sync({ cursor: 0, mode: 'legacy', onEvent: async () => {}, onBatch: async batch => { cursors.push(batch.nextCursor) } })
  expect(cursors).toEqual([2, 4, 6])
  expect(result).toEqual({ nextCursor: 6, events: 3, mode: 'legacy' })
  await instance.close()
})
test('overlapping operations are refused without tearing down the active sync', async () => {
  const { transport, instance } = await client()
  let release!: () => void
  let reached!: () => void
  const waiting = new Promise<void>(resolve => { reached = resolve })
  const stored = new Promise<void>(resolve => { release = resolve })
  const first = instance.sync({ cursor: 0, mode: 'legacy', onEvent: async () => { reached(); await stored }, onBatch: async () => {} })
  await waiting
  await expect(instance.sync({ cursor: 0, onEvent: async () => {}, onBatch: async () => {} })).rejects.toThrow('Another Oura operation')
  expect(transport.closed).toBe(false)
  release()
  await expect(first).resolves.toMatchObject({ nextCursor: 111 })
  await instance.close()
})
test('a native GATT write that never settles is bounded and tears down the session', async () => {
  const transport = new ScriptedTransport()
  transport.write = async () => new Promise<void>(() => {})
  const protocol = await createOuraProtocol()
  const instance = new OuraBleClient(transport, protocol, { ioTimeoutMs: 5 })
  await expect(instance.open(key)).rejects.toThrow('timeout')
  expect(transport.closed).toBe(true)
})
test('a native GATT read that never settles is bounded and tears down the session', async () => {
  const transport = new ScriptedTransport()
  transport.read = async () => new Promise<Uint8Array>(() => {})
  const protocol = await createOuraProtocol()
  const instance = new OuraBleClient(transport, protocol, { ioTimeoutMs: 5 })
  await expect(instance.open(key)).rejects.toThrow('timeout')
  expect(transport.closed).toBe(true)
})
test('a teardown error preserves the original failure', async () => {
  const transport = new ScriptedTransport({ missingSummary: true })
  const protocol = await createOuraProtocol()
  const instance = new OuraBleClient(transport, protocol)
  await instance.open(key)
  transport.close = async () => { transport.closed = true; throw new Error('radio close failed') }
  try {
    await instance.sync({ cursor: 0, mode: 'legacy', onEvent: async () => { throw new Error('storage failed') }, onBatch: async () => {} })
    throw new Error('unexpected success')
  }
  catch (error) {
    expect(error).toBeInstanceOf(AggregateError)
    expect((error as AggregateError).errors.map(item => item.message)).toEqual(['storage failed', 'radio close failed'])
  }
})
async function liveClient() {
  let now = 10
  const transport = new ScriptedTransport()
  const originalWrite = transport.write.bind(transport)
  transport.write = async value => {
    if (hex(value).startsWith('2f032202')) {
      transport.writes.push(value.slice())
      transport.queue.push(bytes('2f03230200'))
      if (value[4] === 3) transport.queue.push(bytes('2f082802000200005913'))
    }
    else await originalWrite(value)
  }
  const originalRead = transport.read.bind(transport)
  transport.read = async (timeoutMs?: number) => {
    if (!transport.queue.length) { now += timeoutMs || 1; throw new OuraTransportError('timeout') }
    now++
    return originalRead()
  }
  const protocol = await createOuraProtocol()
  const instance = new OuraBleClient(transport, protocol, { now: () => now })
  await instance.open(key)
  return { transport, instance }
}
test('live heart rate ends at its deadline and confirms automatic mode restoration', async () => {
  const { transport, instance } = await liveClient()
  const samples: number[] = []
  await instance.heartRate(20, sample => { samples.push(sample.bpm) })
  expect(samples).toEqual([70])
  expect(transport.writes.map(hex).filter(value => value.startsWith('2f032202'))).toEqual(['2f03220203', '2f03220201'])
  await instance.close()
})
test('a failed live callback still restores automatic mode before disconnecting', async () => {
  const { transport, instance } = await liveClient()
  await expect(instance.heartRate(20, () => { throw new Error('consumer failed') })).rejects.toThrow('consumer failed')
  expect(transport.writes.map(hex)).toContain('2f03220201')
  expect(transport.closed).toBe(true)
})
test('closing from a live callback writes automatic mode before disconnecting', async () => {
  const { transport, instance } = await liveClient()
  await instance.heartRate(20, async () => { await instance.close() })
  expect(transport.writes.map(hex)).toContain('2f03220201')
  expect(transport.closed).toBe(true)
})
class UnconfiguredTransport extends ScriptedTransport {
  installed = false
  persisted = false
  rejectInstall = false
  sensitivePayload: Uint8Array | null = null
  async write(value: Uint8Array) {
    if (hex(value).startsWith('2f112d') && !this.installed) {
      this.writes.push(value.slice())
      this.queue.push(bytes('2f022e02'))
    }
    else if (value[0] === 0x24) {
      expect(this.persisted).toBe(true)
      this.sensitivePayload = value
      this.writes.push(value.slice())
      this.installed = !this.rejectInstall
      this.queue.push(packet(0x25, [this.rejectInstall ? 5 : 0]))
    }
    else await super.write(value)
  }
}
test('initial setup stores the key before installing it and verifies fresh authentication', async () => {
  const transport = new UnconfiguredTransport({ ring5: true })
  const instance = new OuraBleClient(transport, await createOuraProtocol())
  let stored: Uint8Array | null = null
  await instance.pair({ key, confirmUnconfigured: true, persistKey: async candidate => { stored = candidate.slice(); transport.persisted = true } })
  expect(stored as Uint8Array | null).toEqual(key)
  expect(transport.installed).toBe(true)
  expect(transport.writes.filter(value => value[0] === 0x24)).toHaveLength(1)
  expect(transport.sensitivePayload!.every(value => value === 0)).toBe(true)
  expect(transport.writes.map(hex)).toContain('160102')
  await instance.close()
})
test('key storage failure leaves an unconfigured ring unchanged', async () => {
  const transport = new UnconfiguredTransport()
  const instance = new OuraBleClient(transport, await createOuraProtocol())
  await expect(instance.pair({ key, confirmUnconfigured: true, persistKey: async () => { throw new Error('Keychain unavailable') } })).rejects.toThrow('Keychain unavailable')
  expect(transport.writes.some(value => value[0] === 0x24)).toBe(false)
  expect(transport.closed).toBe(true)
})
test('initial setup never overwrites a configured ring, even with its correct key', async () => {
  const transport = new ScriptedTransport()
  const instance = new OuraBleClient(transport, await createOuraProtocol())
  let persisted = false
  await expect(instance.pair({ key, confirmUnconfigured: true, persistKey: async () => { persisted = true } })).rejects.toThrow('already has this pairing')
  expect(persisted).toBe(false)
  expect(transport.writes.some(value => value[0] === 0x24)).toBe(false)
})
test('unconfigured rings are reported as needing setup during normal connection', async () => {
  const transport = new UnconfiguredTransport()
  const instance = new OuraBleClient(transport, await createOuraProtocol())
  await expect(instance.open(key)).rejects.toThrow('initial pairing-key setup')
  expect(transport.writes.some(value => value[0] === 0x24)).toBe(false)
})
test('a rejected key install is not reported as paired and retains the status', async () => {
  const transport = new UnconfiguredTransport()
  transport.rejectInstall = true
  const instance = new OuraBleClient(transport, await createOuraProtocol())
  await expect(instance.pair({ key, confirmUnconfigured: true, persistKey: async () => { transport.persisted = true } })).rejects.toThrow('key setup (status 5)')
  expect(transport.installed).toBe(false)
  expect(transport.closed).toBe(true)
})
