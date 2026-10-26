import { $ } from 'bun'
if (process.platform !== 'darwin') throw new Error('The Swift native binding test requires macOS')
const zig = process.env.ZIG_OURA || (await Bun.file('pantry/.bin/zig').exists() ? './pantry/.bin/zig' : 'zig')
const zigTarget = process.arch === 'arm64' ? 'aarch64-macos.13.0' : 'x86_64-macos.13.0'
const swiftTarget = process.arch === 'arm64' ? 'arm64-apple-macosx13.0' : 'x86_64-apple-macosx13.0'
await $`${zig} build -Dtarget=${zigTarget} -Doptimize=ReleaseFast`
await $`xcrun swiftc -target ${swiftTarget} -O -I include -L zig-out/lib -loura bindings/swift/OuraSession.swift test/SwiftSmoke.swift -o zig-out/bin/oura-swift-smoke`
await $`./zig-out/bin/oura-swift-smoke`
