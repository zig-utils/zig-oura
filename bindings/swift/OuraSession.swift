import Foundation
import Security
import ZigOura

public struct OuraNativeError: Error {
    public let code: Int32
    public let authenticationResult: Int32
    public let keySetupResult: Int32
    public init(code: Int32, authenticationResult: Int32, keySetupResult: Int32 = -1) {
        self.code = code; self.authenticationResult = authenticationResult; self.keySetupResult = keySetupResult
    }
}
public struct OuraNativeOutput {
    public let kind: UInt32
    public let tag: UInt32
    public let timestampDeciseconds: UInt32
    public let timestampMilliseconds: UInt64
    public let count: UInt32
    public let bytesLeft: UInt32
    public let auxiliary: UInt32
    public let value: Double
    public let data: Data
}
public struct OuraNativeSample {
    public let kind: UInt32
    public let index: UInt32
    public let intervalMilliseconds: UInt32
    public let value: Double
}

/// Own on a serial actor/queue. GATT, monotonic time, Keychain and durable
/// storage belong to the application. All wire/state/crypto work runs in Zig.
public final class OuraNativeSession {
    private let storage: UnsafeMutableRawPointer
    private let context: OpaquePointer
    private let scratch: UnsafeMutablePointer<UInt8>
    private let input: UnsafeMutablePointer<UInt8>
    private let samples: UnsafeMutablePointer<OuraSample>
    private var feeding = false
    private var closed = false

    public init() throws {
        guard oura_abi_version() == 1 else { throw OuraNativeError(code: -3, authenticationResult: -1) }
        let size = Int(oura_context_size())
        storage = .allocate(byteCount: size, alignment: Int(oura_context_align()))
        context = OpaquePointer(storage)
        scratch = .allocate(capacity: 65535)
        input = .allocate(capacity: 8192)
        samples = .allocate(capacity: 1024)
        let status = oura_context_init(context, size, scratch, 65535)
        if status < 0 {
            samples.deallocate(); input.deallocate(); scratch.deallocate(); storage.deallocate()
            throw OuraNativeError(code: status, authenticationResult: -1)
        }
    }
    deinit {
        oura_close(context)
        samples.deallocate(); input.deallocate(); scratch.deallocate(); storage.deallocate()
    }
    private func check(_ code: Int32) throws {
        if code < 0 { throw OuraNativeError(code: code, authenticationResult: oura_auth_result(context), keySetupResult: oura_key_result(context)) }
    }
    private func available(_ idle: Bool = false) throws {
        if closed || (idle && feeding) { throw OuraNativeError(code: -6, authenticationResult: -1) }
    }
    private func output() throws -> OuraNativeOutput {
        guard let pointer = oura_output(context) else { throw OuraNativeError(code: -6, authenticationResult: -1) }
        let value = pointer.pointee
        let data: Data
        if value.length > 0, let bytes = value.data { data = Data(bytes: bytes, count: Int(value.length)) }
        else { data = Data() }
        return OuraNativeOutput(kind: value.kind, tag: value.tag, timestampDeciseconds: value.timestamp_ds,
            timestampMilliseconds: value.timestamp_ms, count: value.count, bytesLeft: value.bytes_left,
            auxiliary: value.auxiliary, value: value.value, data: data)
    }
    public func begin(key: Data, monotonicMilliseconds: UInt64) throws -> OuraNativeOutput {
        try available(true)
        guard key.count == 16 else { throw OuraNativeError(code: -1, authenticationResult: -1) }
        try key.withUnsafeBytes { bytes in
            try check(oura_begin(context, bytes.bindMemory(to: UInt8.self).baseAddress, key.count, monotonicMilliseconds))
        }
        return try output()
    }
    /// Caller must persist the generated key in Keychain before installing it.
    public static func generatePairingKey() throws -> Data {
        var key = Data(count: 16)
        let status = key.withUnsafeMutableBytes { bytes in SecRandomCopyBytes(kSecRandomDefault, 16, bytes.baseAddress!) }
        guard status == errSecSuccess else { throw OuraNativeError(code: -4, authenticationResult: -1) }
        return key
    }
    public func installInitialKey(_ key: Data, confirmUnconfigured: Bool, monotonicMilliseconds: UInt64) throws -> OuraNativeOutput {
        try available(true)
        guard confirmUnconfigured && key.count == 16 else { throw OuraNativeError(code: -6, authenticationResult: -1) }
        try key.withUnsafeBytes { bytes in
            try check(oura_install_key(context, bytes.bindMemory(to: UInt8.self).baseAddress, key.count, monotonicMilliseconds))
        }
        return try output()
    }
    public func sync(extended: Bool, cursor: UInt32, limit: UInt16, monotonicMilliseconds: UInt64) throws -> OuraNativeOutput {
        try available(true)
        try check(oura_sync(context, extended ? 1 : 0, cursor, limit, monotonicMilliseconds))
        return try output()
    }
    /// Each event callback must durably accept the record before returning.
    /// For kind 4, persist timestampDeciseconds as the next checkpoint, then
    /// call commitBatch(). A failed callback closes the context without commit.
    public func receive(_ notification: Data, monotonicMilliseconds: UInt64, consume: (OuraNativeOutput) throws -> Void) throws {
        try available(true)
        guard !notification.isEmpty && notification.count <= 8192 else { throw OuraNativeError(code: -1, authenticationResult: -1) }
        feeding = true
        defer { feeding = false }
        notification.copyBytes(to: input, count: notification.count)
        do {
            var offset = 0
            while offset < notification.count {
                try check(oura_receive(context, input.advanced(by: offset), notification.count - offset, monotonicMilliseconds))
                let consumed = Int(oura_consumed(context))
                guard consumed > 0 && consumed <= notification.count - offset else { throw OuraNativeError(code: -1, authenticationResult: -1) }
                offset += consumed
                while true {
                    let next = try output()
                    if next.kind == 0 { break }
                    try consume(next)
                    try available()
                    if next.kind != 3 { break }
                    try check(oura_accept(context))
                    try check(oura_next(context))
                }
            }
        }
        catch { close(); throw error }
    }
    public func commitBatch() throws -> UInt32 {
        try available()
        var cursor: UInt32 = 0
        try check(oura_commit(context, &cursor))
        return cursor
    }
    public func request(operation: UInt32, argument: UInt32 = 0, value: UInt32 = 0) throws -> Data {
        try available(true)
        try check(oura_request(context, operation, argument, value))
        return try output().data
    }
    public func decode(tag: UInt8, body: Data) throws -> [OuraNativeSample] {
        try available()
        guard body.count <= 254 else { throw OuraNativeError(code: -10, authenticationResult: -1) }
        return try body.withUnsafeBytes { bytes in
            let count = oura_decode_samples(tag, bytes.bindMemory(to: UInt8.self).baseAddress, body.count, samples, 1024)
            try check(count)
            return (0..<Int(count)).map { index in
                let sample = samples[index]
                return OuraNativeSample(kind: sample.kind, index: sample.index, intervalMilliseconds: sample.interval_ms, value: sample.value)
            }
        }
    }
    public func tick(monotonicMilliseconds: UInt64) throws {
        try available()
        try check(oura_tick(context, monotonicMilliseconds))
    }
    public func close() {
        if closed { return }
        closed = true
        oura_close(context)
        input.initialize(repeating: 0, count: 8192)
    }
}
