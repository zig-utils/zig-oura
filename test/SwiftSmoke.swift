import Foundation

@main
struct SwiftSmoke {
    static func main() throws {
        let randomKey = try OuraNativeSession.generatePairingKey()
        precondition(randomKey.count == 16)
        let session = try OuraNativeSession()
        let key = Data(0..<16)
        let request = try session.begin(key: key, monotonicMilliseconds: 0)
        precondition(request.kind == 1 && request.data == Data([0x2f, 1, 0x2b]))
        var reply = Data()
        try session.receive(Data([0x2f, 16, 0x2c] + Array(0..<15)), monotonicMilliseconds: 1) { output in reply = output.data }
        precondition(reply.count == 19 && reply[2] == 0x2d)
        try session.receive(Data([0x2f, 2, 0x2e, 0]), monotonicMilliseconds: 2) { output in precondition(output.kind == 2) }
        _ = try session.sync(extended: false, cursor: 0, limit: 255, monotonicMilliseconds: 3)
        let history = Data([0x5d, 6, 100, 0, 0, 0, 60, 40, 0x11, 6, 1, 0, 0, 0, 0, 0])
        var events = 0
        var checkpoint: UInt32 = 0
        try session.receive(history, monotonicMilliseconds: 4) { output in
            if output.kind == 3 {
                let samples = try session.decode(tag: UInt8(output.tag), body: output.data)
                precondition(samples.map(\.value) == [60, 40])
                events += 1
            }
            if output.kind == 4 {
                precondition(events == 1 && output.timestampDeciseconds == 101)
                checkpoint = try session.commitBatch()
            }
        }
        precondition(checkpoint == 101)
        session.close()
        let initial = try OuraNativeSession()
        _ = try initial.begin(key: key, monotonicMilliseconds: 0)
        try initial.receive(Data([0x2f, 16, 0x2c] + Array(0..<15)), monotonicMilliseconds: 1) { _ in }
        try initial.receive(Data([0x2f, 2, 0x2e, 2]), monotonicMilliseconds: 2) { precondition($0.kind == 8) }
        let install = try initial.installInitialKey(key, confirmUnconfigured: true, monotonicMilliseconds: 3)
        precondition(install.kind == 1 && install.auxiliary == 1 && install.data == Data([0x24, 16]) + key)
        try initial.receive(Data([0x25, 1, 0]), monotonicMilliseconds: 4) { precondition($0.data == request.data) }
        try initial.receive(Data([0x2f, 16, 0x2c] + Array(0..<15)), monotonicMilliseconds: 5) { precondition($0.auxiliary == 1) }
        try initial.receive(Data([0x2f, 2, 0x2e, 0]), monotonicMilliseconds: 6) { precondition($0.kind == 2) }
        initial.close()
        print("Swift native binding: Zig authentication, decoding and checkpoint verified")
    }
}
