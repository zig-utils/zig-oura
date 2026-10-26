import { OuraProtocolError, type HistoryMode, type OuraProtocol, type Output, type RingEvent } from './protocol'

/** Native GATT host: subscribe before any write. Reads must queue every
 * notification, reject overflow/disconnect and be cancelled by close(). */
export interface OuraTransport {
  write(bytes: Uint8Array): Promise<void>
  read(timeoutMs: number): Promise<Uint8Array>
  close(): Promise<void>
}
export interface BatchProgress { nextCursor: number, events: number, totalEvents: number, bytesLeft: number, mode: HistoryMode }
export interface SyncOptions {
  cursor: number
  mode?: HistoryMode | 'auto'
  /** Persist raw records idempotently, scoped to this ring and reset generation. */
  onEvent(event: RingEvent): Promise<void>
  /** Durably commit this checkpoint together with the accepted records. */
  onBatch(batch: BatchProgress): Promise<void>
  maxBatches?: number
  timeoutMs?: number
}
type BatchOutcome = { unsupported: true } | { unsupported: false, progress: BatchProgress }
export class OuraTransportError extends Error {
  constructor(public readonly code: 'timeout' | 'disconnected' | 'overflow', message = `Oura transport ${code}`) { super(message); this.name = 'OuraTransportError' }
}
export class OuraBleClient {
  private opened = false
  private closed = false
  private busy = false
  private liveRestore: Uint8Array | null = null
  private readonly now: () => number
  private readonly ioTimeoutMs: number
  constructor(private readonly transport: OuraTransport, private readonly protocol: OuraProtocol, options: { now?: () => number, ioTimeoutMs?: number } = {}) {
    this.now = options.now || (() => performance.now())
    this.ioTimeoutMs = options.ioTimeoutMs ?? 6000
    if (!Number.isFinite(this.ioTimeoutMs) || this.ioTimeoutMs < 1 || this.ioTimeoutMs > 120000) throw new RangeError('Invalid Oura transport deadline')
  }
  private async operation<T>(run: () => Promise<T>): Promise<T> {
    if (this.closed) throw new Error('Oura client is closed')
    if (this.busy) throw new Error('Another Oura operation is running')
    this.busy = true
    try { return await run() }
    catch (error) {
      try { await this.close() }
      catch (cleanup) { throw new AggregateError([error, cleanup], error instanceof Error ? error.message : 'Oura operation failed') }
      throw error
    }
    finally { this.busy = false }
  }
  private async timed<T>(work: Promise<T>, timeoutMs: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined
    try { return await Promise.race([work, new Promise<never>((resolve, reject) => { timer = setTimeout(() => reject(new OuraTransportError('timeout')), timeoutMs) })]) }
    finally { if (timer !== undefined) clearTimeout(timer) }
  }
  private async send(bytes: Uint8Array): Promise<void> { await this.timed(this.transport.write(bytes), Math.min(3000, this.ioTimeoutMs)) }
  private async read(timeoutMs: number): Promise<Uint8Array> {
    const deadline = Math.min(timeoutMs, this.ioTimeoutMs)
    return this.timed(this.transport.read(deadline), deadline)
  }
  private async write(output: Output): Promise<void> {
    if (output.kind !== 'write') throw new Error('Oura did not produce a request')
    try { await this.send(output.bytes) }
    finally { if (output.sensitive) output.bytes.fill(0) }
  }
  private async pump<T>(deadline: number, handle: (output: Output) => Promise<T | undefined>): Promise<T> {
    while (!this.closed) {
      const remaining = deadline - this.now()
      if (remaining <= 0) throw new OuraProtocolError(-5)
      this.protocol.tick(this.now())
      const bytes = await this.read(Math.max(1, Math.ceil(Math.min(remaining, 6000))))
      if (!bytes.length) throw new Error('Oura transport returned an empty notification')
      let answer: T | undefined
      for (const output of this.protocol.receive(bytes, this.now())) {
        if (output.kind === 'write') await this.write(output)
        const result = await handle(output)
        if (result !== undefined) answer = result
      }
      if (answer !== undefined) return answer
    }
    throw new Error('Oura client is closed')
  }
  private async exchange(operation: number, argument: number, value: number, tag: number, extended?: number): Promise<Uint8Array> {
    await this.send(this.protocol.request(operation, argument, value))
    return this.pump(this.now() + 3000, async output => output.kind === 'packet' && output.tag === tag && (extended === undefined || output.payload[0] === extended) ? output.payload : undefined)
  }
  /** Uses an existing 16-byte pairing key. Never replaces it or resets a ring. */
  async open(key: Uint8Array, options: { setupStream?: boolean } = {}): Promise<void> {
    return this.operation(async () => {
      if (this.opened) throw new Error('Oura client is already open')
      await this.write(this.protocol.begin(key, this.now()))
      await this.pump(this.now() + 6000, async output => {
        if (output.kind === 'unconfigured') throw new OuraProtocolError(-4, 2)
        return output.kind === 'ready' ? true : undefined
      })
      this.opened = true
      if (options.setupStream !== false) await this.setupStream()
    })
  }
  /** Initial setup only. The ring must itself report an unconfigured state.
   * Persist the host-generated random key before it is installed on the ring. */
  async pair(options: { key: Uint8Array, confirmUnconfigured: true, persistKey: (key: Uint8Array) => Promise<void>, setupStream?: boolean }): Promise<void> {
    return this.operation(async () => {
      if (this.opened || options.confirmUnconfigured !== true || typeof options.persistKey !== 'function')
        throw new Error('Explicit initial pairing and durable key storage are required')
      await this.write(this.protocol.begin(options.key, this.now()))
      const state = await this.pump<'unconfigured' | 'ready'>(this.now() + 6000, async output => output.kind === 'unconfigured' ? 'unconfigured' : output.kind === 'ready' ? 'ready' : undefined)
      if (state !== 'unconfigured') throw new Error('Oura already has this pairing; open it with the existing key')
      const staged = options.key.slice()
      try { await options.persistKey(staged) }
      finally { staged.fill(0) }
      if (this.closed) throw new Error('Oura client is closed')
      await this.write(this.protocol.installKey(options.key, this.now()))
      await this.pump(this.now() + 9000, async output => {
        if (output.kind === 'unconfigured') throw new OuraProtocolError(-4, 2)
        return output.kind === 'ready' ? true : undefined
      })
      this.opened = true
      if (options.setupStream !== false) await this.setupStream()
    })
  }
  private async setupStream(): Promise<void> {
    const hardware = await this.exchange(8, 0, 0, 0x19)
    if (!hardware.length || hardware[0] !== 0) throw new Error('Oura rejected the hardware information request')
    const name = new TextDecoder().decode(hardware.subarray(1)).replace(/\0+$/, '').trim()
    for (const page of [0, 1]) await this.exchange(4, page, 0, 0x2f, 0x02)
    // Captured Ring 5 setup. Older hardware must not receive its registrations.
    if (name.split('_').at(-1) !== '05') return
    await this.exchange(7, 2, 0, 0x17)
    for (const [category, flags] of [[0x14, 0x1000], [0x18, 0x1000], [0x28, 0x0900], [0x34, 0x0400], [0x04, 0x1000], [0x08, 0x1000]] as const)
      await this.exchange(9, category, flags, 0x19)
    for (const [operation, argument, reply] of [[10, 2, 0x21], [10, 4, 0x21], [11, 0, 0x04], [10, 0x0b, 0x21], [10, 0x0d, 0x21], [10, 3, 0x21], [10, 0x0b, 0x21], [10, 0x10, 0x21]] as const)
      await this.exchange(operation, argument, 0, 0x2f, reply)
  }
  async sync(options: SyncOptions): Promise<{ nextCursor: number, events: number, mode: HistoryMode }> {
    return this.operation(async () => {
      if (!this.opened) throw new Error('Authenticate Oura before syncing')
      if (!Number.isSafeInteger(options.cursor) || options.cursor < 0 || options.cursor > 0xffffffff)
        throw new RangeError('Invalid Oura history cursor')
      if (options.mode !== undefined && !['auto', 'legacy', 'extended'].includes(options.mode))
        throw new RangeError('Unknown Oura history mode')
      let cursor = options.cursor
      let mode: HistoryMode = options.mode === 'legacy' ? 'legacy' : 'extended'
      const maxBatches = options.maxBatches ?? 10000
      const timeoutMs = options.timeoutMs ?? 600000
      if (!Number.isSafeInteger(maxBatches) || maxBatches < 1 || !Number.isFinite(timeoutMs) || timeoutMs <= 0)
        throw new RangeError('Oura sync needs positive batch and time limits')
      const deadline = this.now() + timeoutMs
      let total = 0
      let tailBatches = 0
      for (let batch = 0; batch < maxBatches; batch++) {
        if (this.now() >= deadline) throw new OuraProtocolError(-5)
        // Release buffered data; cursor-addressed fetches follow. No ack-fetch,
        // history erase, device clock write or factory reset is sent.
        await this.exchange(13, 0, 0, 0x29)
        await this.write(this.protocol.sync(mode, cursor, mode === 'legacy' ? 255 : 4096, this.now()))
        const outcome = await this.pump<BatchOutcome>(Math.min(deadline, this.now() + 120000), async output => {
          if (output.kind === 'event') {
            await options.onEvent(output.event)
            this.protocol.accept()
          }
          if (output.kind === 'unsupported') return { unsupported: true } as const
          if (output.kind === 'batch') {
            const progress = { nextCursor: output.nextCursor, events: output.events, totalEvents: total + output.events, bytesLeft: output.bytesLeft, mode }
            await options.onBatch(progress)
            const committed = this.protocol.commit()
            if (committed !== output.nextCursor) throw new Error('Oura checkpoint changed during persistence')
            return { unsupported: false, progress } as const
          }
          return undefined
        })
        if (outcome.unsupported) {
          if (options.mode === 'extended' || mode === 'legacy') throw new OuraProtocolError(-3)
          // Explicit extended-API rejection, with no delivered events. This is
          // capability negotiation, never a retry of a partially accepted batch.
          mode = 'legacy'
          continue
        }
        const progress = outcome.progress
        total = progress.totalEvents
        if (progress.nextCursor <= cursor) {
          if (progress.bytesLeft === 0) return { nextCursor: cursor, events: total, mode }
          throw new Error('Oura reports a backlog without cursor progress')
        }
        cursor = progress.nextCursor
        // Gen 3 can report zero bytes while full batches remain. Confirm the
        // drain; a bounded small live tail avoids chasing new events forever.
        tailBatches = progress.bytesLeft === 0 && progress.events < 32 ? tailBatches + 1 : 0
        if (tailBatches >= 3) return { nextCursor: cursor, events: total, mode }
      }
      throw new Error('Oura sync reached its batch limit; resume from the saved checkpoint')
    })
  }
  /** Live mode lasts only for this call and is restored even when its callback fails. */
  async heartRate(durationMs: number, onSample: (sample: { bpm: number, ibiMs: number }) => void | Promise<void>): Promise<void> {
    return this.operation(async () => {
      if (!this.opened || !Number.isFinite(durationMs) || durationMs <= 0 || durationMs > 600000) throw new RangeError('Oura live duration must be between 1 and 600000 ms on an authenticated client')
      this.liveRestore = this.protocol.request(6, 2, 1)
      const start = await this.exchange(6, 2, 3, 0x2f, 0x23)
      if (start.length < 3 || start[1] !== 2 || start[2] !== 0) throw new Error('Oura rejected live heart rate')
      let failed = false
      let failure: unknown
      try {
        const deadline = this.now() + durationMs
        while (this.now() < deadline) {
          let bytes: Uint8Array
          try { bytes = await this.read(Math.max(1, Math.ceil(Math.min(6000, deadline - this.now())))) }
          catch (error) {
            if (error instanceof OuraTransportError && error.code === 'timeout' && this.now() >= deadline) break
            throw error
          }
          for (const output of this.protocol.receive(bytes, this.now())) {
            if (output.kind === 'heart-rate') await onSample({ bpm: output.bpm, ibiMs: output.ibiMs })
            if (this.closed) return
          }
        }
      }
      catch (error) { failed = true; failure = error }
      finally {
        if (!this.closed) {
          try {
            const stopped = await this.exchange(6, 2, 1, 0x2f, 0x23)
            if (stopped.length < 3 || stopped[1] !== 2 || stopped[2] !== 0) throw new Error('Oura did not confirm restoring automatic heart rate')
            this.liveRestore = null
          }
          catch (error) {
            if (failed) throw new AggregateError([failure, error], failure instanceof Error ? failure.message : 'Oura live callback failed')
            throw error
          }
        }
      }
      if (failed) throw failure
    })
  }
  async close(): Promise<void> {
    if (this.closed) return
    this.closed = true
    this.opened = false
    const restore = this.liveRestore
    this.liveRestore = null
    let failure: unknown
    let failed = false
    try { if (restore) await this.send(restore) }
    catch (error) { failed = true; failure = error }
    this.protocol.close()
    try { await this.timed(this.transport.close(), this.ioTimeoutMs) }
    catch (error) {
      if (failed) throw new AggregateError([failure, error], 'Oura teardown failed')
      throw error
    }
    if (failed) throw failure
  }
}
