import { expect, test } from 'bun:test'
import { connectOuraBluetooth, ouraBluetoothAvailable, type OuraNativeBluetooth } from '../bindings/bluetooth'

function radio() {
  const writes: number[][] = []
  const connections: unknown[] = []
  let closed = 0
  const bluetooth: OuraNativeBluetooth = {
    getState: async () => ({ streaming: true }), scan: async () => [], stopScan: async () => {},
    connect: async options => { connections.push(options) },
    read: async () => [0x2f, 1, 0x2c],
    write: async ({ bytes }) => { writes.push(bytes) }, disconnect: async () => { closed++ },
  }
  return { bluetooth, writes, connections, closed: () => closed }
}
test('a selected native channel connects without implicitly authenticating or installing a key', async () => {
  const r = radio()
  const client = await connectOuraBluetooth(r.bluetooth, 'ring-3')
  expect(r.connections).toEqual([{ id: 'ring-3', service: '98ed0001-a541-11e4-b6a0-0002a5d5c51b', write: '98ed0002-a541-11e4-b6a0-0002a5d5c51b', notify: '98ed0003-a541-11e4-b6a0-0002a5d5c51b', stream: true }])
  expect(r.writes).toEqual([])
  await client.close()
  expect(r.closed()).toBe(1)
})
test('a failed native connect closes the acquired connection', async () => {
  const r = radio()
  r.bluetooth.connect = async () => { throw new Error('radio failed') }
  await expect(connectOuraBluetooth(r.bluetooth, 'ring-3')).rejects.toThrow('radio failed')
  expect(r.closed()).toBe(1)
})
test('account cancellation during connection closes the link without writing', async () => {
  const r = radio()
  let current = true
  r.bluetooth.connect = async () => { current = false }
  await expect(connectOuraBluetooth(r.bluetooth, 'ring-3', { current: () => current })).rejects.toThrow('cancelled')
  expect(r.closed()).toBe(1)
  expect(r.writes).toHaveLength(0)
})
test('unavailable streaming is detected before the radio is acquired', async () => {
  const r = radio()
  r.bluetooth.getState = async () => ({ streaming: false })
  expect(await ouraBluetoothAvailable(r.bluetooth)).toBe(false)
  await expect(connectOuraBluetooth(r.bluetooth, 'ring-3')).rejects.toThrow('Update the app')
  expect(r.connections).toHaveLength(0)
})
