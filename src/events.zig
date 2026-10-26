const std = @import("std");
const p = @import("protocol.zig");
pub const max_body = 254; // Extended length byte minus the shortest timestamp varint.
pub const Event = struct {
    tag: u8,
    timestamp_ds: u32,
    timestamp_ms: u64,
    body: []const u8,
    pub fn parse(packet: p.Packet) p.Error!Event {
        if (packet.tag < 0x41 or packet.payload.len < 4) return error.Malformed;
        const ticks = std.mem.readInt(u32, packet.payload[0..4], .little);
        return .{ .tag = packet.tag, .timestamp_ds = ticks, .timestamp_ms = @as(u64, ticks) * 100, .body = packet.payload[4..] };
    }
};
pub const Kind = enum(u8) { heart_rate, rmssd, spo2, temperature, ibi, sleep_stage, met };
/// Event time is ring-relative. Index/interval preserve sample placement without
/// inventing Unix dates or claiming that raw samples are Oura daily scores.
pub const Sample = struct { kind: Kind, value: f64, index: u16, interval_ms: u32 = 0 };
fn put(out: []Sample, count: *usize, sample: Sample) p.Error!void {
    if (count.* == out.len) return error.NoSpace;
    out[count.*] = sample;
    count.* += 1;
}
pub fn bpm(ibi: u16) ?u16 {
    return if (ibi >= 300 and ibi <= 2000) @intCast(@as(u32, 60000) / ibi) else null;
}
pub const HeartRate = struct { bpm: u16, ibi_ms: u16 };
pub fn liveHeartRate(packet: p.Packet) p.Error!?HeartRate {
    if (packet.extended() != 0x28) return null;
    const bytes = packet.payload;
    if (bytes.len < 8) return error.Truncated;
    if (bytes[1] != @backingInt(p.Feature.daytime_hr)) return null;
    const raw = std.mem.readInt(u16, bytes[6..8], .little);
    if (raw >> 12 != 1) return null;
    const ibi = raw & 0x0fff;
    return if (bpm(ibi)) |value| .{ .bpm = value, .ibi_ms = ibi } else null;
}
pub const Latest = struct { feature: u8, heart_rate: ?u16 = null, spo2: ?u8 = null };
pub fn latest(packet: p.Packet) p.Error!Latest {
    if (packet.extended() != 0x25 or packet.payload.len < 7) return error.Malformed;
    const bytes = packet.payload;
    if (bytes[2] != 0) return error.Unsupported;
    const data = bytes[7..];
    var result: Latest = .{ .feature = bytes[1] };
    switch (result.feature) {
        2 => {
            if (data.len < 2) return error.Truncated;
            result.heart_rate = bpm(std.mem.readInt(u16, data[0..2], .little));
        },
        3, 4 => {
            if (data.len < 5) return error.Truncated;
            if (data[4] >= 30 and data[4] <= 240) result.heart_rate = data[4];
            if (result.feature == 4 and data[3] > 0 and data[3] <= 100) result.spo2 = data[3];
        },
        else => return error.Unsupported,
    }
    return result;
}
/// Known bodies decode to samples; unknown bodies remain available losslessly.
pub fn decode(event: Event, out: []Sample) p.Error!usize {
    const body = event.body;
    if (body.len > max_body) return error.TooLarge;
    var count: usize = 0;
    switch (event.tag) {
        0x5d => {
            if (body.len == 0 or body.len % 2 != 0) return error.Malformed;
            var i: usize = 0;
            while (i < body.len) : (i += 2) {
                const index: u16 = @intCast(i / 2);
                if (body[i] >= 30 and body[i] <= 240) try put(out, &count, .{ .kind = .heart_rate, .value = @floatFromInt(body[i]), .index = index, .interval_ms = 300000 });
                if (body[i + 1] != 0 and body[i + 1] != 255) try put(out, &count, .{ .kind = .rmssd, .value = @floatFromInt(body[i + 1]), .index = index, .interval_ms = 300000 });
            }
        },
        0x46, 0x69, 0x75 => {
            if (body.len == 0 or body.len % 2 != 0) return error.Malformed;
            var i: usize = 0;
            while (i < body.len) : (i += 2) {
                const value = std.mem.readInt(i16, body[i..][0..2], .little);
                if (value < -4000 or value > 8500) return error.Malformed;
                try put(out, &count, .{ .kind = .temperature, .value = @as(f64, @floatFromInt(value)) / 100, .index = @intCast(i / 2) });
            }
        },
        0x80 => {
            if (body.len == 0 or body.len % 2 != 0) return error.Malformed;
            var i: usize = 0;
            while (i < body.len) : (i += 2) {
                const ibi = (@as(u16, body[i]) << 3) | (body[i + 1] & 7);
                if (((body[i + 1] >> 3) & 3) == 1) {
                    if (bpm(ibi)) |value| {
                        try put(out, &count, .{ .kind = .ibi, .value = @floatFromInt(ibi), .index = @intCast(i / 2) });
                        try put(out, &count, .{ .kind = .heart_rate, .value = @floatFromInt(value), .index = @intCast(i / 2) });
                    }
                }
            }
        },
        0x6f => {
            if (body.len < 2) return error.Malformed;
            // Header and 0xff continuation marker are not measurements.
            for (body[1..], 0..) |value, index| {
                if (value > 0 and value <= 100) try put(out, &count, .{ .kind = .spo2, .value = @floatFromInt(value), .index = @intCast(index), .interval_ms = 1000 });
            }
        },
        0x4b, 0x4e, 0x5a => {
            if (body.len < 2) return error.Malformed;
            for (body[1..], 0..) |value, index| {
                for (0..4) |part| {
                    const shift: u3 = @intCast(6 - part * 2);
                    try put(out, &count, .{ .kind = .sleep_stage, .value = @floatFromInt((value >> shift) & 3), .index = @intCast(index * 4 + part), .interval_ms = if (event.tag == 0x5a) 30000 else 0 });
                }
            }
        },
        0x50 => {
            if (body.len < 2) return error.Malformed;
            for (body[1..], 0..) |value, index| {
                const met = if (value <= 128) @as(f64, @floatFromInt(value)) / 10 else 12.8 + @as(f64, @floatFromInt(value - 128)) / 5;
                try put(out, &count, .{ .kind = .met, .value = met, .index = @intCast(index) });
            }
        },
        else => return error.Unsupported,
    }
    return count;
}
/// Standard RMSSD over explicitly supplied, validated inter-beat intervals.
pub fn rmssd(intervals_ms: []const u16) ?f64 {
    if (intervals_ms.len < 2) return null;
    var sum: f64 = 0;
    for (intervals_ms, 0..) |value, index| {
        if (bpm(value) == null) return null;
        if (index > 0) {
            const delta = @as(f64, @floatFromInt(value)) - @as(f64, @floatFromInt(intervals_ms[index - 1]));
            sum += delta * delta;
        }
    }
    return @sqrt(sum / @as(f64, @floatFromInt(intervals_ms.len - 1)));
}

test "captured live IBI validity gates heart rate" {
    var iter: p.Iterator = .{ .bytes = &.{ 0x2f, 8, 0x28, 2, 0, 2, 0, 0, 0x59, 0x13 } };
    const packet = (try iter.next()).?;
    const sample = (try liveHeartRate(packet)).?;
    try std.testing.expectEqual(@as(u16, 857), sample.ibi_ms);
    try std.testing.expectEqual(@as(u16, 70), sample.bpm);
    try std.testing.expect((try liveHeartRate(.{ .tag = 0x2f, .payload = &.{ 0x28, 2, 0, 2, 0, 0, 0x59, 0x03 } })) == null);
}
test "known history bodies decode with units and retain unknown raw records" {
    var samples: [16]Sample = undefined;
    const event = try Event.parse(.{ .tag = 0x5d, .payload = &.{ 100, 0, 0, 0, 60, 40, 62, 45, 61, 50 } });
    try std.testing.expectEqual(@as(usize, 6), try decode(event, &samples));
    try std.testing.expectEqual(@as(f64, 50), samples[5].value);
    try std.testing.expectEqual(@as(u32, 300000), samples[5].interval_ms);
    const raw = try Event.parse(.{ .tag = 0xff, .payload = &.{ 100, 0, 0, 0, 0xaa, 0xbb } });
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, raw.body);
    try std.testing.expectError(error.Unsupported, decode(raw, &samples));
    try std.testing.expectError(error.Malformed, Event.parse(.{ .tag = 0x5d, .payload = &.{1} }));
    try std.testing.expectError(error.NoSpace, decode(event, samples[0..1]));
    try std.testing.expectApproxEqAbs(@as(f64, 17.320508), rmssd(&.{ 800, 820, 810, 830 }).?, 0.00001);
    try std.testing.expect(rmssd(&.{ 0, 800 }) == null);
}
