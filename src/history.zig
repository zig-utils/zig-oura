const std = @import("std");
const p = @import("protocol.zig");
const Event = @import("events.zig").Event;
pub const Error = p.Error || error{ Overflow, MissingSummary, CountMismatch, IncompleteEnvelope, WrongBuffer, Rejected, PendingEvent, NoPendingEvent, InvalidState };

const Varint = struct { value: u64, used: usize };
fn varint(bytes: []const u8) Error!Varint {
    var value: u64 = 0;
    for (bytes[0..@min(10, bytes.len)], 0..) |byte, index| {
        if (index == 9 and byte > 1) return error.Overflow;
        value |= @as(u64, byte & 127) << @as(u6, @intCast(index * 7));
        if (byte & 128 == 0) return .{ .value = value, .used = index + 1 };
    }
    return error.Truncated;
}

/// Borrowed bundle view. Consume it before feeding the assembler again.
pub const Bundle = struct {
    bytes: []const u8,
    last_ms: ?u64 = null,
    last_cursor: ?u32 = null,
    pub fn next(self: *Bundle) Error!?Event {
        if (self.bytes.len == 0) return null;
        if (self.bytes.len < 3) return error.Truncated;
        const length: usize = self.bytes[2];
        if (self.bytes[1] < 0x41) return error.Malformed;
        if (self.bytes.len < length + 3) return error.Truncated;
        const payload = self.bytes[3 .. length + 3];
        const timestamp = try varint(payload);
        // First timestamp is absolute within EACH envelope, including reboot.
        const ms = if (self.last_ms != null and timestamp.value < 100000000)
            std.math.add(u64, self.last_ms.?, timestamp.value) catch return error.Overflow
        else
            timestamp.value;
        if (ms / 100 > std.math.maxInt(u32)) return error.Overflow;
        var cursor: u32 = @intCast(ms / 100);
        // Preserve sub-decisecond events at distinct cursor positions, as the
        // reference does, while retaining their actual ring milliseconds too.
        if (self.last_cursor) |previous| {
            if (timestamp.value > 0 and cursor <= previous) cursor = std.math.add(u32, previous, 1) catch return error.Overflow;
        }
        const result: Event = .{ .tag = self.bytes[1], .timestamp_ds = cursor, .timestamp_ms = ms, .body = payload[timestamp.used..] };
        self.bytes = self.bytes[length + 3 ..];
        self.last_ms = ms;
        self.last_cursor = cursor;
        return result;
    }
};

/// Ring 5 length-prefixes bundles across arbitrary notification boundaries.
/// Scratch belongs to the caller; overlarge bundles fail rather than allocate.
pub const Assembler = struct {
    scratch: []u8,
    header: [2]u8 = @splat(0),
    header_used: u2 = 0,
    expected: ?u16 = null,
    used: usize = 0,
    pub const Feed = struct { consumed: usize, bundle: ?Bundle = null };
    pub fn complete(self: Assembler) bool {
        return self.expected == null and self.header_used == 0;
    }
    pub fn push(self: *Assembler, bytes: []const u8) Error!Feed {
        var consumed: usize = 0;
        while (consumed < bytes.len) {
            if (self.expected == null) {
                while (self.header_used < 2 and consumed < bytes.len) {
                    self.header[self.header_used] = bytes[consumed];
                    self.header_used += 1;
                    consumed += 1;
                }
                if (self.header_used < 2) break;
                self.header_used = 0;
                const length = std.mem.readInt(u16, &self.header, .little);
                if (length > self.scratch.len) return error.TooLarge;
                if (length == 0) continue;
                self.expected = length;
                self.used = 0;
            }
            const take = @min(self.expected.? - self.used, bytes.len - consumed);
            @memcpy(self.scratch[self.used .. self.used + take], bytes[consumed .. consumed + take]);
            consumed += take;
            self.used += take;
            if (self.used == self.expected.?) {
                self.expected = null;
                return .{ .consumed = consumed, .bundle = .{ .bytes = self.scratch[0..self.used] } };
            }
        }
        return .{ .consumed = consumed };
    }
};

pub const Summary = struct {
    events: u16,
    bytes_left: u32,
    sleep_progress: u8,
    pub fn parse(packet: p.Packet, mode: p.HistoryMode) Error!Summary {
        if (mode == .legacy) {
            if (packet.tag != 0x11 or packet.payload.len < 6) return error.Malformed;
            return .{ .events = packet.payload[0], .sleep_progress = packet.payload[1], .bytes_left = std.mem.readInt(u32, packet.payload[2..6], .little) };
        }
        if (packet.extended() != 0x42 or packet.payload.len < 10) return error.Malformed;
        const bytes = packet.payload;
        if (bytes[8] != 0) return error.WrongBuffer;
        if (bytes[9] != 0) return error.Rejected;
        return .{ .events = std.mem.readInt(u16, bytes[1..3], .little), .sleep_progress = bytes[3], .bytes_left = std.mem.readInt(u32, bytes[4..8], .little) };
    }
};

/// A batch has three barriers: every event accepted by durable storage, a valid
/// summary, then an explicit commit. No timeout or partial bundle advances it.
pub const Batch = struct {
    mode: p.HistoryMode,
    cursor: u32,
    maximum: u16,
    seen: u16 = 0,
    candidate: u32,
    pending: ?u32 = null,
    summary: ?Summary = null,
    pub fn init(mode: p.HistoryMode, cursor: u32, maximum: u16) Batch {
        return .{ .mode = mode, .cursor = cursor, .candidate = cursor, .maximum = maximum };
    }
    pub fn offer(self: *Batch, event: Event) Error!void {
        if (self.summary != null) return error.InvalidState;
        if (self.pending != null) return error.PendingEvent;
        if (self.seen == self.maximum) return error.TooLarge;
        if (event.timestamp_ds == std.math.maxInt(u32)) return error.Overflow;
        self.pending = event.timestamp_ds;
    }
    pub fn accept(self: *Batch) Error!void {
        const timestamp = self.pending orelse return error.NoPendingEvent;
        self.seen += 1;
        // Older replays do not ratchet the checkpoint forward forever.
        if (timestamp >= self.cursor) self.candidate = @max(self.candidate, timestamp + 1);
        self.pending = null;
    }
    pub fn finish(self: *Batch, packet: p.Packet, envelopes_complete: bool) Error!Summary {
        if (self.summary != null) return error.InvalidState;
        if (self.pending != null) return error.PendingEvent;
        if (!envelopes_complete) return error.IncompleteEnvelope;
        const summary = try Summary.parse(packet, self.mode);
        if (summary.events != self.seen) return error.CountMismatch;
        self.summary = summary;
        return summary;
    }
    /// Persist this value together with the accepted records before requesting
    /// the next batch. The library never acknowledges/deletes ring history.
    pub fn commit(self: *Batch) Error!u32 {
        if (self.summary == null) return error.MissingSummary;
        self.cursor = self.candidate;
        return self.cursor;
    }
};

test "split Ring 5 envelope and per-envelope absolute timestamp" {
    var scratch: [64]u8 = undefined;
    var assembler: Assembler = .{ .scratch = &scratch };
    try std.testing.expect((try assembler.push(&.{ 6, 0, 0xaa })).bundle == null);
    try std.testing.expect(!assembler.complete());
    var bundle = (try assembler.push(&.{ 0x43, 3, 100, 0xbb, 0xcc })).bundle.?;
    const event = (try bundle.next()).?;
    try std.testing.expectEqual(@as(u32, 1), event.timestamp_ds);
    try std.testing.expectEqualSlices(u8, &.{ 0xbb, 0xcc }, event.body);
    try std.testing.expect((try bundle.next()) == null);
    bundle = (try assembler.push(&.{ 7, 0, 0xaa, 0x43, 4, 0xc8, 1, 0xdd, 0xee })).bundle.?;
    try std.testing.expectEqual(@as(u32, 2), (try bundle.next()).?.timestamp_ds);
    try std.testing.expect(assembler.complete());
}
test "bounded buffers and malformed varints fail without a checkpoint" {
    var scratch: [4]u8 = undefined;
    var assembler: Assembler = .{ .scratch = &scratch };
    try std.testing.expectError(error.TooLarge, assembler.push(&.{ 255, 255 }));
    var bundle: Bundle = .{ .bytes = &.{ 0xaa, 0x43, 1, 0x80 } };
    try std.testing.expectError(error.Truncated, bundle.next());
    bundle.bytes = &.{ 0xaa, 0x43, 10, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2 };
    try std.testing.expectError(error.Overflow, bundle.next());
}
test "checkpoint requires durable acceptance, complete envelope, and matching summary" {
    var batch = Batch.init(.legacy, 100, 255);
    const event: Event = .{ .tag = 0x43, .timestamp_ds = 110, .timestamp_ms = 11000, .body = "data" };
    try batch.offer(event);
    try std.testing.expectError(error.PendingEvent, batch.offer(event));
    try std.testing.expectError(error.MissingSummary, batch.commit());
    try batch.accept();
    const summary: p.Packet = .{ .tag = 0x11, .payload = &.{ 1, 0, 0, 0, 0, 0 } };
    try std.testing.expectError(error.IncompleteEnvelope, batch.finish(summary, false));
    try std.testing.expectError(error.CountMismatch, batch.finish(.{ .tag = 0x11, .payload = &.{ 2, 0, 0, 0, 0, 0 } }, true));
    try std.testing.expectEqual(@as(u32, 100), batch.cursor);
    _ = try batch.finish(summary, true);
    try std.testing.expectEqual(@as(u32, 111), try batch.commit());
}
test "older replay does not advance and extended result/buffer failures are explicit" {
    var batch = Batch.init(.extended, 100, 4096);
    try batch.offer(.{ .tag = 0x43, .timestamp_ds = 99, .timestamp_ms = 9900, .body = "data" });
    try batch.accept();
    try std.testing.expectError(error.Rejected, batch.finish(.{ .tag = 0x2f, .payload = &.{ 0x42, 1, 0, 0, 0, 0, 0, 0, 0, 1 } }, true));
    _ = try batch.finish(.{ .tag = 0x2f, .payload = &.{ 0x42, 1, 0, 0, 0, 0, 0, 0, 0, 0 } }, true);
    try std.testing.expectEqual(@as(u32, 100), try batch.commit());
}
