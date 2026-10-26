import { OuraBleClient, type OuraTransport } from './client'
import { OURA_NOTIFY, OURA_SERVICE, OURA_WRITE, createOuraProtocol, type OuraProtocol } from './protocol'

export const OURA_BLE = { service: OURA_SERVICE, write: OURA_WRITE, notify: OURA_NOTIFY } as const
export interface OuraNearbyDevice { id: string, name: string, rssi?: number }
/** Ordered native GATT stream, subscribed before connect() resolves. */
export interface OuraNativeBluetooth {
  getState(): Promise<{ streaming?: boolean }>
  scan(options: { services: string[], timeoutMs: number }): Promise<OuraNearbyDevice[]>
  stopScan(): Promise<unknown>
  connect(options: { id: string, service: string, write: string, notify: string, stream: boolean }): Promise<unknown>
  read(options: { timeoutMs: number }): Promise<number[]>
  write(options: { bytes: number[] }): Promise<unknown>
  disconnect(): Promise<unknown>
}
export async function ouraBluetoothAvailable(bluetooth: OuraNativeBluetooth | null | undefined): Promise<boolean> {
  return !!bluetooth?.read && !!bluetooth?.write && (await bluetooth.getState()).streaming === true
}
/** Connect one explicitly selected ring. Caller then chooses open(existingKey)
 * or explicit initial pair(); this function never installs keys or scans. */
export async function connectOuraBluetooth(bluetooth: OuraNativeBluetooth, deviceId: string, options: { current?: () => boolean, protocol?: () => Promise<OuraProtocol> } = {}): Promise<OuraBleClient> {
  const check = (): void => { if (options.current && !options.current()) throw new Error('Oura connection cancelled') }
  if (!deviceId || deviceId.length > 256) throw new RangeError('Select an Oura Bluetooth device')
  check()
  if (!await ouraBluetoothAvailable(bluetooth)) throw new Error('Update the app to use direct Oura Bluetooth')
  check()
  // Instantiate before taking the radio: unsupported native hosts fail cleanly.
  const protocol = await (options.protocol ?? createOuraProtocol)()
  let connected = false
  const transport: OuraTransport = {
    async write(bytes) {
      check()
      const copy = [...bytes]
      try { await bluetooth.write({ bytes: copy }); check() }
      finally { copy.fill(0) }
    },
    async read(timeoutMs) {
      check()
      const bytes = await bluetooth.read({ timeoutMs })
      check()
      if (!Array.isArray(bytes) || !bytes.length || bytes.length > 8192 || bytes.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new Error('Invalid Oura Bluetooth notification')
      return Uint8Array.from(bytes)
    },
    async close() { if (connected) { connected = false; await bluetooth.disconnect() } },
  }
  try {
    check()
    // Mark ownership before awaiting: a failed/cancelled native connect can
    // already have opened a link, which must be closed too.
    connected = true
    await bluetooth.connect({ id: deviceId, ...OURA_BLE, stream: true })
    check()
    return new OuraBleClient(transport, protocol)
  }
  catch (error) {
    protocol.close()
    try { await transport.close() }
    catch (cleanup) { throw new AggregateError([error, cleanup], error instanceof Error ? error.message : 'Oura connection failed') }
    throw error
  }
}
