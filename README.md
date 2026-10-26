# zig-oura

Native Oura Ring BLE protocol and history sync, based on
[open_oura](https://github.com/Th0rgal/open_oura). The protocol, AES challenge,
event decoding, and checkpoint state machine run in Zig. Native hosts use a C
ABI; the optional TypeScript client uses the same compiled code through WASM.

## Status

Experimental interoperability implementation for the shared Ring 3/4/5 protocol.
Captured Ring 5 records, synthetic failure cases, the C ABI, and the Swift
binding are tested. Physical pairing and firmware compatibility have not yet
been validated with this implementation. Tests are not a hardware certification.

Implemented:

- Allocation-free native framing, AES-128 nonce authentication, firmware/battery
  parsing, command builders, and live heart-rate validation.
- Legacy history and split/coalesced Ring 5 extended envelopes, retaining every
  event body, including unknown event types.
- HR/5-minute RMSSD, SpO2, temperature, quality-checked IBI, sleep-stage and MET
  decoders; standard RMSSD over supplied inter-beat intervals.
- Incremental native sessions with caller-owned memory, deadlines, complete
  batch validation, explicit durable acceptance, and checkpoint commits.
- Ring 5 stream registration, capability reads, bounded native GATT operations,
  explicit legacy negotiation, small-tail drain handling, and live-mode teardown.
- Stable C ABI, Swift binding, and an independent WASM instance per JS client.

A ring already configured with an Oura app needs its **existing 16-byte pairing
key**, not its account password or cloud OAuth token. This library does not
extract an existing key, replace a configured pairing, or reset the ring. The application owns consent,
Bluetooth permissions, secure key storage, and the native GATT connection.

Oura's proprietary models and firmware are not included. This package does not
claim to reproduce official Sleep/Readiness/Activity scores. Raw ring readings
and locally derived values must retain their provenance; an application can
keep Oura's cloud integration for data unavailable directly from the ring.

## Build and verify

Pinned tools are in `deps.yaml`: Bun 1.4.4 and Zig
`0.17.0-dev.1441+d5181a9c9`. No external runtime dependencies are required by the
Zig library. `better-dx` supplies the JS development tools.

```sh
pantry install
bun install --frozen-lockfile
zig build
zig build test
bun run build
bun run typecheck
bun test ./test
bun run lint
bun run bench
# macOS, using the native library rather than WASM:
bun run test:swift
```

`zig build` installs `liboura.a`, `oura.h`, and the Swift module map.
`zig build wasm` builds the portable module. `bun run build` embeds that module
and builds the TypeScript entry point. `test/ring5-capture.json` records the
immutable reference revision and independent expected records; the tests replay
the capture at every possible envelope split boundary.

The benchmark measures native C-ABI decoding of a small HRV event into four
readings. It excludes Bluetooth, storage and application callbacks. It is a
local throughput measurement, not a claim about radio sync speed.

## Native Zig

Add an immutable release source archive as a Zig dependency and import its
`oura` module:

```zig
const oura = @import("oura");
var scratch: [65535]u8 = undefined;
var session = oura.session.Session.init(&scratch);
defer session.close();
const first = try session.begin(pairing_key, monotonic_milliseconds);
// Send first.write through the Oura GATT write characteristic.
// Feed every complete packet from protocol.Iterator to session.receive().
```

GATT identifiers are `protocol.service_uuid`, `write_uuid`, and `notify_uuid`.
Subscribe to the Oura service's notification/indication characteristics before
writing; newer rings can expose additional notifying characteristics.

During history sync, persist every `.event`, then call `acceptEvent()` and
`next()` until `.none`. At `.batch`, durably persist its candidate checkpoint
with the accepted records before `commitBatch()`. Never advance a checkpoint
on a timeout, partial envelope, count mismatch or failed storage operation.
The client sends no history deletion, reset, firmware update, or ack-fetch.

Cursors and event timestamps are **ring-relative deciseconds**, not Unix dates.
Extended events also retain their original ring milliseconds. Wall-clock
anchors and ring/reset identity must be retained by storage; do not attach raw
history to the current date or reuse another ring's cursor.

## C and Swift

`include/oura.h` documents output kinds and error codes. Allocate the reported
context size/alignment and independent scratch memory. A context has one owner;
independent contexts can run on different threads. Output pointers are borrowed
until the next call. `test/abi.c` is a compiled C usage example.

`bindings/swift/OuraSession.swift` owns those buffers and wraps the same native
C ABI. Import `ZigOura` using `include/module.modulemap`, link `liboura.a`, and
own the session on a serial actor or queue. Its `receive` callback must finish
persisting each event before returning. `test/SwiftSmoke.swift` exercises native
authentication, event decoding and checkpointing without JavaScript or WASM.

## TypeScript

The portable npm-format package is `@zig-utils/oura`. GitHub releases include
its package tarball; the native source is published through Pantry.

```ts
import { OuraBleClient, createOuraProtocol } from '@zig-utils/oura'

const protocol = await createOuraProtocol()
const client = new OuraBleClient(transport, protocol)
try {
  await client.open(existingPairingKey)
  await client.sync({
    cursor: await store.cursorFor(ringId, resetGeneration),
    onEvent: async event => { await store.acceptIdempotently(event) },
    onBatch: async batch => { await store.commitCheckpoint(batch.nextCursor) },
  })
}
finally { await client.close() }
```

The host supplies `write(bytes)`, `read(timeoutMs)`, and `close()`. Queue
notifications before any write, preserve their order, reject overflow and
disconnect, and cancel outstanding operations on close. The client also bounds
I/O itself and preserves the original failure if teardown fails. Radio reconnect
policy belongs to the application and resumes from its last durable checkpoint.

`createOuraProtocol` uses WASM. A host without WebAssembly must inject an
`OuraProtocol` backed by the native C ABI; this package has no separate JS
implementation of the wire protocol or cryptography.

To stream HR briefly, use `client.heartRate(durationMs, onSample)`. It confirms
restoration of automatic mode after a normal stop or callback failure; closing
an active stream attempts restoration before disconnecting. Protocol logs must
never include pairing keys or authentication payloads.

## Initial setup of an unconfigured ring

An existing configured ring must use `open(existingPairingKey)`. A missing key
is not permission to overwrite the pairing. `pair()` proceeds only after the
ring itself reports the unconfigured authentication result; a configured ring
cannot enter the key-install state.

For an already unconfigured ring, generate a cryptographically random 16-byte
key (`crypto.getRandomValues` on a supported host or
`OuraNativeSession.generatePairingKey()` on Apple platforms), then:

```ts
await client.pair({
  key: generatedKey,
  confirmUnconfigured: true,
  persistKey: async key => { await keychain.storeFor(ringId, key) },
})
```

The callback must durably copy the key before resolving. Its temporary argument
is erased afterward. The client installs the key only after storage succeeds,
then performs a new nonce challenge to verify authentication. Retain the stored
key if the radio disconnects during installation: the ring may already have
accepted it. Resume with `open()` and the same stored key. Never generate a new
key merely because a connection failed.

The Swift/C session exposes the same guarded install operation; the host must
persist the key first. Treat write outputs with `auxiliary == 1` as sensitive:
never log or retain their payloads, and erase host copies after writing. A GATT
transport must remain bound to one ring for the lifetime of a client; it must
not silently reconnect to another device during setup or history sync.

## Releases

Follow the zig-starter workflow: conventional commits, a clean source tree,
Pantry-managed version/changelog/commit/tag, then the release workflow.

```sh
bun run release:preview
bun run release          # pantry release patch --yes
# Or release:minor / release:major
```

Review `CHANGELOG.md` and the release source. The tag workflow rebuilds and tests
the package, uses `stacksjs/action-releaser`, and publishes the Zig source through
Pantry using `PANTRY_TOKEN`. Versioning is shared by `package.json` and
`build.zig.zon`; do not hand-edit one during a release.

## Attribution

Protocol reference: Thomas Marchand's MIT-licensed `Th0rgal/open_oura`, revision
`e57c43ce5fe0cf9a646afa790bda3731be767507`. See [NOTICE.md](NOTICE.md) for its
license and provenance. This project is independent of Oura.
