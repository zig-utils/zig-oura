import { wasmBytes } from './wasm-bytes'
export const OURA_SERVICE = '98ed0001-a541-11e4-b6a0-0002a5d5c51b'
export const OURA_WRITE = '98ed0002-a541-11e4-b6a0-0002a5d5c51b'
export const OURA_NOTIFY = '98ed0003-a541-11e4-b6a0-0002a5d5c51b'
export type HistoryMode = 'legacy' | 'extended'
export interface RingEvent { tag: number, timestampDs: number, timestampMs: number, body: Uint8Array }
export interface Sample { kind: 'heart-rate' | 'rmssd' | 'spo2' | 'temperature' | 'ibi' | 'sleep-stage' | 'met', value: number, index: number, intervalMs: number }
export type Output = { kind: 'none' } | { kind: 'write', bytes: Uint8Array, sensitive?: true } | { kind: 'ready' }
  | { kind: 'event', event: RingEvent } | { kind: 'batch', events: number, bytesLeft: number, nextCursor: number, sleepProgress: number }
  | { kind: 'heart-rate', bpm: number, ibiMs: number }
  | { kind: 'packet', tag: number, payload: Uint8Array } | { kind: 'unsupported' } | { kind: 'unconfigured' }
export interface OuraProtocol {
  begin(key: Uint8Array, nowMs: number): Output
  installKey(key: Uint8Array, nowMs: number): Output
  sync(mode: HistoryMode, cursor: number, limit: number, nowMs: number): Output
  receive(bytes: Uint8Array, nowMs: number): Generator<Output>
  accept(): void
  commit(): number
  tick(nowMs: number): void
  request(operation: number, argument?: number, value?: number): Uint8Array
  decode(event: RingEvent): Sample[]
  close(): void
}
export class OuraProtocolError extends Error {
  constructor(public readonly code: number, public readonly authResult = -1, public readonly keySetupResult = -1) {
    const reasons: Record<number, string> = {
      [-1]: 'Malformed Oura packet', [-2]: 'Oura buffer capacity exceeded', [-3]: 'Unsupported Oura operation',
      [-4]: 'Oura rejected this pairing key', [-5]: 'Oura response timed out', [-6]: 'Invalid Oura session state',
      [-7]: 'Incomplete Oura history batch: event count mismatch', [-8]: 'Incomplete Oura history envelope or summary',
      [-9]: 'Oura rejected the history request', [-10]: 'Oura protocol size or timestamp overflow',
    }
    super(code === -4 && keySetupResult > 0 ? `Oura rejected initial key setup (status ${keySetupResult})` : code === -4 && authResult === 2 ? 'Oura needs explicit initial pairing-key setup' : (reasons[code] || 'Oura protocol failed'))
    this.name = 'OuraProtocolError'
  }
}
interface Exports {
  memory: WebAssembly.Memory
  oura_abi_version(): number
  oura_wasm_init(): number
  oura_input_ptr(): number
  oura_input_capacity(): number
  oura_decode_input_ptr(): number
  oura_begin(context: number, key: number, size: number, now: bigint): number
  oura_install_key(context: number, key: number, size: number, now: bigint): number
  oura_sync(context: number, extended: number, cursor: number, limit: number, now: bigint): number
  oura_receive(context: number, input: number, size: number, now: bigint): number
  oura_next(context: number): number
  oura_accept(context: number): number
  oura_wasm_commit(context: number): number
  oura_wasm_cursor(): number
  oura_tick(context: number, now: bigint): number
  oura_close(context: number): void
  oura_auth_result(context: number): number
  oura_key_result(context: number): number
  oura_consumed(context: number): number
  oura_request(context: number, operation: number, argument: number, value: number): number
  oura_output_kind(context: number): number
  oura_output_data(context: number): number
  oura_output_length(context: number): number
  oura_output_tag(context: number): number
  oura_output_ticks(context: number): number
  oura_output_milliseconds(context: number): bigint
  oura_output_count(context: number): number
  oura_output_left(context: number): number
  oura_output_auxiliary(context: number): number
  oura_output_value(context: number): number
  oura_wasm_decode(tag: number, length: number): number
  oura_sample_kind(index: number): number
  oura_sample_index(index: number): number
  oura_sample_interval(index: number): number
  oura_sample_value(index: number): number
}
function uint(value: number, maximum = 0xffffffff): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) throw new RangeError('Expected an unsigned Oura protocol integer')
  return value
}
const time = (value: number): bigint => BigInt(uint(Math.floor(value), Number.MAX_SAFE_INTEGER))

/** Every instance has independent native state. Hosts without WebAssembly must
 * inject an OuraProtocol backed by include/oura.h; there is no JS codec copy. */
export async function createOuraProtocol(): Promise<OuraProtocol> {
  if (typeof WebAssembly === 'undefined') throw new Error('This host must provide the native Zig Oura protocol binding')
  const { instance } = await WebAssembly.instantiate(new Uint8Array(wasmBytes))
  const api = instance.exports as unknown as Exports
  if (api.oura_abi_version() !== 1) throw new Error('Unsupported Zig Oura ABI')
  const context = api.oura_wasm_init()
  const pointer = api.oura_input_ptr()
  let feeding = false
  let closed = false
  function check(code: number): number {
    if (code < 0) throw new OuraProtocolError(code, api.oura_auth_result(context), api.oura_key_result(context))
    return code
  }
  function alive(): void { if (closed) throw new OuraProtocolError(-6) }
  function idle(): void { alive(); if (feeding) throw new OuraProtocolError(-6) }
  function copy(pointer: number, length: number): Uint8Array { return new Uint8Array(api.memory.buffer, pointer, length).slice() }
  function output(): Output {
    switch (api.oura_output_kind(context)) {
      case 0: return { kind: 'none' }
      case 1: return { kind: 'write', bytes: copy(api.oura_output_data(context), api.oura_output_length(context)), ...(api.oura_output_auxiliary(context) === 1 ? { sensitive: true as const } : {}) }
      case 2: return { kind: 'ready' }
      case 3: return { kind: 'event', event: { tag: api.oura_output_tag(context), timestampDs: api.oura_output_ticks(context), timestampMs: Number(api.oura_output_milliseconds(context)), body: copy(api.oura_output_data(context), api.oura_output_length(context)) } }
      case 4: return { kind: 'batch', events: api.oura_output_count(context), bytesLeft: api.oura_output_left(context), nextCursor: api.oura_output_ticks(context), sleepProgress: api.oura_output_auxiliary(context) }
      case 5: return { kind: 'heart-rate', bpm: api.oura_output_value(context), ibiMs: api.oura_output_auxiliary(context) }
      case 6: return { kind: 'packet', tag: api.oura_output_tag(context), payload: copy(api.oura_output_data(context), api.oura_output_length(context)) }
      case 7: return { kind: 'unsupported' }
      case 8: return { kind: 'unconfigured' }
      default: throw new Error('Unknown Zig Oura output')
    }
  }
  function keyRequest(key: Uint8Array, run: () => number): Output {
    idle()
    if (!(key instanceof Uint8Array) || key.length !== 16) throw new RangeError('Oura pairing keys contain exactly 16 bytes')
    const input = new Uint8Array(api.memory.buffer, pointer, 16)
    input.set(key)
    try { check(run()); return output() }
    finally { input.fill(0) }
  }
  return {
    begin(key, nowMs) { return keyRequest(key, () => api.oura_begin(context, pointer, 16, time(nowMs))) },
    installKey(key, nowMs) { return keyRequest(key, () => api.oura_install_key(context, pointer, 16, time(nowMs))) },
    sync(mode, cursor, limit, nowMs) {
      idle()
      if (mode !== 'legacy' && mode !== 'extended') throw new RangeError('Unknown Oura history mode')
      check(api.oura_sync(context, Number(mode === 'extended'), uint(cursor), uint(limit, 65535), time(nowMs)))
      return output()
    },
    *receive(bytes, nowMs) {
      idle()
      if (!bytes.length || bytes.length > api.oura_input_capacity()) throw new RangeError('Invalid Oura notification size')
      feeding = true
      try {
        new Uint8Array(api.memory.buffer, pointer, bytes.length).set(bytes)
        let offset = 0
        while (offset < bytes.length) {
          check(api.oura_receive(context, pointer + offset, bytes.length - offset, time(nowMs)))
          const consumed = api.oura_consumed(context)
          if (!consumed || consumed > bytes.length - offset) throw new Error('Invalid Zig Oura packet boundary')
          offset += consumed
          while (true) {
            const next = output()
            if (next.kind === 'none') break
            yield next
            alive()
            if (next.kind !== 'event') break
            check(api.oura_next(context))
          }
        }
      }
      finally { feeding = false }
    },
    accept() { alive(); check(api.oura_accept(context)) },
    commit() { alive(); check(api.oura_wasm_commit(context)); return api.oura_wasm_cursor() },
    tick(nowMs) { alive(); check(api.oura_tick(context, time(nowMs))) },
    request(operation, argument = 0, value = 0) {
      idle()
      check(api.oura_request(context, uint(operation), uint(argument), uint(value)))
      const next = output()
      if (next.kind !== 'write') throw new Error('Zig Oura request did not produce a command')
      return next.bytes
    },
    decode(event) {
      alive()
      if (event.body.length > 254) throw new RangeError('Oura event body exceeds the wire limit')
      new Uint8Array(api.memory.buffer, api.oura_decode_input_ptr(), event.body.length).set(event.body)
      const count = check(api.oura_wasm_decode(uint(event.tag, 255), event.body.length))
      const kinds: Sample['kind'][] = ['heart-rate', 'rmssd', 'spo2', 'temperature', 'ibi', 'sleep-stage', 'met']
      return Array.from({ length: count }, (_, index) => ({ kind: kinds[api.oura_sample_kind(index)]!, index: api.oura_sample_index(index), intervalMs: api.oura_sample_interval(index), value: api.oura_sample_value(index) }))
    },
    close() { if (!closed) { api.oura_close(context); new Uint8Array(api.memory.buffer, pointer, api.oura_input_capacity()).fill(0); closed = true } },
  }
}
