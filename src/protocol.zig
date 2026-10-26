const std = @import("std");
pub const Error = error{ NoSpace, TooLarge, Truncated, Malformed, Unsupported };
pub const service_uuid = "98ed0001-a541-11e4-b6a0-0002a5d5c51b";
pub const write_uuid = "98ed0002-a541-11e4-b6a0-0002a5d5c51b";
pub const notify_uuid = "98ed0003-a541-11e4-b6a0-0002a5d5c51b";
pub const max_payload = 255;
pub const max_packet = max_payload + 2;
pub const Feature = enum(u8) { daytime_hr = 2, exercise_hr = 3, spo2 = 4, resting_hr = 8, charging_control = 14 };
pub const FeatureMode = enum(u8) { off = 0, automatic = 1, requested = 2, connected_live = 3 };
pub const HistoryMode = enum { legacy, extended };

pub const Packet = struct {
    tag: u8,
    payload: []const u8,
    pub fn extended(self: Packet) ?u8 {
        return if (self.tag == 0x2f and self.payload.len > 0) self.payload[0] else null;
    }
};

/// One notification may contain several packets. Never invent a partial event.
pub const Iterator = struct {
    bytes: []const u8,
    pub fn next(self: *Iterator) Error!?Packet {
        if (self.bytes.len == 0) return null;
        if (self.bytes.len < 2) return error.Truncated;
        const length: usize = self.bytes[1];
        if (self.bytes.len < length + 2) return error.Truncated;
        const packet: Packet = .{ .tag = self.bytes[0], .payload = self.bytes[2 .. length + 2] };
        self.bytes = self.bytes[length + 2 ..];
        return packet;
    }
};

pub fn encode(tag: u8, payload: []const u8, out: []u8) Error![]u8 {
    if (payload.len > max_payload) return error.TooLarge;
    if (out.len < payload.len + 2) return error.NoSpace;
    out[0] = tag;
    out[1] = @intCast(payload.len);
    @memcpy(out[2 .. payload.len + 2], payload);
    return out[0 .. payload.len + 2];
}

pub fn firmware(out: []u8) Error![]u8 {
    return encode(0x08, &.{ 0, 0, 0 }, out);
}
pub fn battery(out: []u8) Error![]u8 {
    return encode(0x0c, &.{}, out);
}
pub fn serial(out: []u8) Error![]u8 {
    return encode(0x18, &.{ 0x08, 0, 0x10 }, out);
}
pub fn nonce(out: []u8) Error![]u8 {
    return encode(0x2f, &.{0x2b}, out);
}
pub fn capabilities(page: u8, out: []u8) Error![]u8 {
    return encode(0x2f, &.{ 0x01, page }, out);
}
pub fn authenticate(block: [16]u8, out: []u8) Error![]u8 {
    var payload: [17]u8 = undefined;
    payload[0] = 0x2d;
    @memcpy(payload[1..], &block);
    return encode(0x2f, &payload, out);
}
/// Raw builder used by the guarded initial-key setup in Session.
pub fn installKey(key: [16]u8, out: []u8) Error![]u8 {
    return encode(0x24, &key, out);
}
pub fn featureLatest(feature: Feature, out: []u8) Error![]u8 {
    return encode(0x2f, &.{ 0x24, @backingInt(feature) }, out);
}
pub fn featureMode(feature: Feature, mode: FeatureMode, out: []u8) Error![]u8 {
    return encode(0x2f, &.{ 0x22, @backingInt(feature), @backingInt(mode) }, out);
}
pub fn subscribe(mode: u8, out: []u8) Error![]u8 {
    if (mode > 2) return error.Unsupported;
    return encode(0x16, &.{mode}, out);
}
pub fn hardware(out: []u8) Error![]u8 {
    return encode(0x18, &.{ 0x18, 0, 0x10 }, out);
}
pub fn eventSubscribe(category: u8, flags: u16, out: []u8) Error![]u8 {
    var payload: [3]u8 = .{ category, 0, 0 };
    std.mem.writeInt(u16, payload[1..3], flags, .little);
    return encode(0x18, &payload, out);
}
pub fn parameter(id: u8, out: []u8) Error![]u8 {
    return encode(0x2f, &.{ 0x20, id }, out);
}
pub fn statePoll(out: []u8) Error![]u8 {
    return encode(0x2f, &.{ 0x03, 1 }, out);
}
pub fn dataFlush(out: []u8) Error![]u8 {
    return encode(0x28, &.{0}, out);
}

/// History cursors are ring-relative deciseconds, never Unix timestamps.
pub fn getEvents(mode: HistoryMode, cursor: u32, limit: u16, out: []u8) Error![]u8 {
    if (limit == 0) return error.Malformed;
    if (mode == .legacy) {
        if (limit > 255) return error.TooLarge;
        var payload: [9]u8 = @splat(0xff);
        std.mem.writeInt(u32, payload[0..4], cursor, .little);
        payload[4] = @intCast(limit);
        return encode(0x10, &payload, out);
    }
    var payload: [12]u8 = @splat(0);
    payload[0] = 0x41;
    std.mem.writeInt(u64, payload[2..10], @as(u64, cursor) * 100, .little);
    std.mem.writeInt(u16, payload[10..12], limit, .little);
    return encode(0x2f, &payload, out);
}

pub const DeviceInfo = struct {
    api: [3]u8,
    firmware: [3]u8,
    bootloader: [3]u8,
    bluetooth: [3]u8,
    mac: [6]u8,
    pub fn parse(packet: Packet) Error!DeviceInfo {
        if (packet.tag != 0x09 or packet.payload.len < 18) return error.Malformed;
        const p = packet.payload;
        return .{ .api = p[0..3].*, .firmware = p[3..6].*, .bootloader = p[6..9].*, .bluetooth = p[9..12].*, .mac = .{ p[17], p[16], p[15], p[14], p[13], p[12] } };
    }
};
pub const Battery = struct {
    percent: u8,
    charging_progress: u8,
    charging_recommended: u8,
    pub fn parse(packet: Packet) Error!Battery {
        if (packet.tag != 0x0d or packet.payload.len < 3 or packet.payload[0] > 100) return error.Malformed;
        return .{ .percent = packet.payload[0], .charging_progress = packet.payload[1], .charging_recommended = packet.payload[2] };
    }
};

test "coalesced notifications retain every packet and reject a truncated tail" {
    var iter: Iterator = .{ .bytes = &.{ 0x0d, 3, 89, 0, 0, 0x2f, 2, 0x2e, 0 } };
    try std.testing.expectEqual(@as(u8, 89), (try Battery.parse((try iter.next()).?)).percent);
    try std.testing.expectEqual(@as(?u8, 0x2e), (try iter.next()).?.extended());
    try std.testing.expect((try iter.next()) == null);
    iter.bytes = &.{ 0x43, 4, 1 };
    try std.testing.expectError(error.Truncated, iter.next());
}
test "request vectors use deciseconds for legacy and milliseconds for Ring 5" {
    var out: [max_packet]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{ 0x2f, 1, 0x2b }, try nonce(&out));
    try std.testing.expectEqualSlices(u8, &.{ 0x10, 9, 1, 0, 0, 0, 255, 255, 255, 255, 255 }, try getEvents(.legacy, 1, 255, &out));
    try std.testing.expectEqualSlices(u8, &.{ 0x2f, 12, 0x41, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0, 16 }, try getEvents(.extended, 1, 4096, &out));
    try std.testing.expectError(error.TooLarge, getEvents(.legacy, 0, 256, &out));
    try std.testing.expectError(error.Malformed, getEvents(.legacy, 0, 0, &out));
    try std.testing.expectError(error.NoSpace, firmware(out[0..2]));
}
