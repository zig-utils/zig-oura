const std = @import("std");
const p = @import("protocol.zig");
const auth = @import("auth.zig");
const events = @import("events.zig");
const h = @import("history.zig");
pub const Error = h.Error || error{ AuthenticationFailed, InvalidNonce, Timeout, Closed, UndrainedInput };
pub const State = enum { idle, nonce, authenticating, unconfigured, installing_key, ready, syncing, batch_ready, failed, closed };
pub const Output = union(enum) { none, write: []const u8, secret_write: []const u8, ready, event: events.Event, batch: h.Summary, heart_rate: events.HeartRate, packet: p.Packet, unsupported, unconfigured };

/// Host owns GATT, a bounded lossless notification queue, monotonic time and
/// storage. All protocol work is native and allocation-free. An output event
/// borrows the notification/scratch until acceptEvent() and next() complete.
pub const Session = struct {
    state: State = .idle,
    last_auth: ?auth.Result = null,
    last_key_result: ?u8 = null,
    key: auth.Key = @splat(0),
    command: [p.max_packet]u8 = undefined,
    assembler: h.Assembler,
    incoming: []const u8 = &.{},
    bundle: ?h.Bundle = null,
    batch: ?h.Batch = null,
    deadline: u64 = 0,
    total_deadline: u64 = 0,
    command_timeout_ms: u32 = 3000,
    history_timeout_ms: u32 = 6000,
    batch_timeout_ms: u32 = 120000,

    pub fn init(scratch: []u8) Session {
        return .{ .assembler = .{ .scratch = scratch } };
    }
    fn fail(self: *Session) void {
        self.state = .failed;
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.command);
        self.incoming = &.{};
        self.bundle = null;
    }
    pub fn close(self: *Session) void {
        self.fail();
        self.batch = null;
        self.state = .closed;
    }
    pub fn tick(self: *Session, now_ms: u64) Error!void {
        if (self.state == .closed) return error.Closed;
        if (self.state == .failed) return error.InvalidState;
        if (self.state == .nonce or self.state == .authenticating or self.state == .installing_key or self.state == .syncing) {
            if (now_ms >= self.deadline or now_ms >= self.total_deadline) {
                self.fail();
                return error.Timeout;
            }
        }
    }
    pub fn begin(self: *Session, key: auth.Key, now_ms: u64) Error!Output {
        if (self.state != .idle) return error.InvalidState;
        self.key = key;
        self.state = .nonce;
        self.deadline = now_ms +| self.command_timeout_ms;
        self.total_deadline = now_ms +| (@as(u64, self.command_timeout_ms) * 2);
        return .{ .write = try p.nonce(&self.command) };
    }
    pub fn startSync(self: *Session, mode: p.HistoryMode, cursor: u32, limit: u16, now_ms: u64) Error!Output {
        if (self.state != .ready) return error.InvalidState;
        const request = try p.getEvents(mode, cursor, limit, &self.command);
        self.batch = h.Batch.init(mode, cursor, limit);
        self.assembler = .{ .scratch = self.assembler.scratch };
        self.incoming = &.{};
        self.bundle = null;
        self.state = .syncing;
        self.deadline = now_ms +| self.history_timeout_ms;
        self.total_deadline = now_ms +| self.batch_timeout_ms;
        return .{ .write = request };
    }
    /// Host consent and durable secure key storage must precede this call.
    /// Existing configured pairings cannot reach this state.
    pub fn installKey(self: *Session, key: auth.Key, now_ms: u64) Error!Output {
        if (self.state != .unconfigured or self.last_auth != .factory_reset) return error.InvalidState;
        self.key = key;
        self.state = .installing_key;
        self.deadline = now_ms +| self.command_timeout_ms;
        self.total_deadline = now_ms +| (@as(u64, self.command_timeout_ms) * 3);
        return .{ .secret_write = try p.installKey(key, &self.command) };
    }
    pub fn receive(self: *Session, packet: p.Packet, now_ms: u64) Error!Output {
        return self.receiveInner(packet, now_ms) catch |err| {
            self.fail();
            return err;
        };
    }
    fn receiveInner(self: *Session, packet: p.Packet, now_ms: u64) Error!Output {
        try self.tick(now_ms);
        switch (self.state) {
            .nonce => {
                if (packet.extended() != 0x2c) return .none;
                const block = try auth.encryptNonce(self.key, packet.payload[1..]);
                std.crypto.secureZero(u8, &self.key);
                self.state = .authenticating;
                self.deadline = now_ms +| self.command_timeout_ms;
                return .{ .secret_write = try p.authenticate(block, &self.command) };
            },
            .authenticating => {
                if (packet.extended() != 0x2e) return .none;
                if (packet.payload.len < 2) return error.Malformed;
                self.last_auth = @fromBackingInt(@intCast(packet.payload[1]));
                if (self.last_auth == .factory_reset) {
                    self.state = .unconfigured;
                    return .unconfigured;
                }
                if (self.last_auth != .success) return error.AuthenticationFailed;
                self.state = .ready;
                return .ready;
            },
            .installing_key => {
                if (packet.tag != 0x25) return .none;
                if (packet.payload.len < 1) return error.Malformed;
                self.last_key_result = packet.payload[0];
                if (packet.payload[0] != 0) return error.AuthenticationFailed;
                std.crypto.secureZero(u8, &self.command);
                self.state = .nonce;
                self.deadline = now_ms +| self.command_timeout_ms;
                return .{ .write = try p.nonce(&self.command) };
            },
            .idle, .ready => {
                if (try events.liveHeartRate(packet)) |reading| return .{ .heart_rate = reading };
                return .{ .packet = packet };
            },
            .syncing => {
                if (self.batch.?.pending != null) return error.PendingEvent;
                if (self.incoming.len != 0 or self.bundle != null) return error.UndrainedInput;
                // Explicit capability rejection can negotiate legacy sync.
                // Never retry a partially delivered extended batch this way.
                if (packet.extended() == 0 and self.batch.?.mode == .extended) {
                    if (self.batch.?.seen != 0 or !self.assembler.complete()) return error.Rejected;
                    self.batch = null;
                    self.state = .ready;
                    return .unsupported;
                }
                if (packet.tag == 0x11 or packet.extended() == 0x42) {
                    const summary = try self.batch.?.finish(packet, self.assembler.complete());
                    self.state = .batch_ready;
                    return .{ .batch = summary };
                }
                if (packet.tag >= 0x41) {
                    const event = try events.Event.parse(packet);
                    try self.batch.?.offer(event);
                    self.deadline = now_ms +| self.history_timeout_ms;
                    return .{ .event = event };
                }
                if (packet.extended() == 0x43) {
                    if (self.batch.?.mode != .extended) return error.Malformed;
                    self.incoming = packet.payload[1..];
                    self.deadline = now_ms +| self.history_timeout_ms;
                    return try self.next();
                }
                return .none;
            },
            else => return error.InvalidState,
        }
    }
    /// Drain all events in the notification before supplying another one.
    pub fn next(self: *Session) Error!Output {
        return self.nextInner() catch |err| {
            self.fail();
            return err;
        };
    }
    fn nextInner(self: *Session) Error!Output {
        if (self.state != .syncing) return error.InvalidState;
        if (self.batch.?.pending != null) return error.PendingEvent;
        while (true) {
            if (self.bundle) |*bundle| {
                if (try bundle.next()) |event| {
                    try self.batch.?.offer(event);
                    return .{ .event = event };
                }
                self.bundle = null;
            }
            if (self.incoming.len == 0) return .none;
            const fed = try self.assembler.push(self.incoming);
            self.incoming = self.incoming[fed.consumed..];
            self.bundle = fed.bundle;
        }
    }
    pub fn acceptEvent(self: *Session) Error!void {
        if (self.state != .syncing) return error.InvalidState;
        try self.batch.?.accept();
    }
    /// Call only after durable storage has accepted this batch and checkpoint.
    pub fn commitBatch(self: *Session) Error!u32 {
        if (self.state != .batch_ready) return error.InvalidState;
        const cursor = try self.batch.?.commit();
        self.state = .ready;
        return cursor;
    }
};

fn authenticated(scratch: []u8) !Session {
    var session = Session.init(scratch);
    _ = try session.begin(@splat(0), 0);
    _ = try session.receive(.{ .tag = 0x2f, .payload = &.{ 0x2c, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 } }, 1);
    _ = try session.receive(.{ .tag = 0x2f, .payload = &.{ 0x2e, 0 } }, 2);
    return session;
}
test "authentication succeeds and clears the pairing key from session memory" {
    var scratch: [64]u8 = undefined;
    var session = try authenticated(&scratch);
    try std.testing.expectEqual(State.ready, session.state);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), &session.key);
    session.close();
    try std.testing.expectError(error.Closed, session.tick(3));
}
test "rejected authentication never starts a history request" {
    var scratch: [64]u8 = undefined;
    var session = Session.init(&scratch);
    _ = try session.begin(@splat(0), 0);
    _ = try session.receive(.{ .tag = 0x2f, .payload = &.{ 0x2c, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 } }, 1);
    try std.testing.expectError(error.AuthenticationFailed, session.receive(.{ .tag = 0x2f, .payload = &.{ 0x2e, 1 } }, 2));
    try std.testing.expectEqual(State.failed, session.state);
    try std.testing.expectEqual(@as(?auth.Result, .rejected), session.last_auth);
    try std.testing.expectError(error.InvalidState, session.startSync(.legacy, 0, 255, 3));
}
test "native session drains split extended history and commits only after acceptance" {
    var scratch: [64]u8 = undefined;
    var session = try authenticated(&scratch);
    _ = try session.startSync(.extended, 0, 4096, 10);
    try std.testing.expect((try session.receive(.{ .tag = 0x2f, .payload = &.{ 0x43, 6, 0, 0xaa } }, 11)) == .none);
    const result = try session.receive(.{ .tag = 0x2f, .payload = &.{ 0x43, 0x43, 3, 100, 0xbb, 0xcc } }, 12);
    try std.testing.expectEqual(@as(u32, 1), result.event.timestamp_ds);
    try session.acceptEvent();
    try std.testing.expect((try session.next()) == .none);
    const summary = try session.receive(.{ .tag = 0x2f, .payload = &.{ 0x42, 1, 0, 0, 0, 0, 0, 0, 0, 0 } }, 13);
    try std.testing.expectEqual(@as(u16, 1), summary.batch.events);
    try std.testing.expectEqual(@as(u32, 2), try session.commitBatch());
    try std.testing.expectEqual(State.ready, session.state);
}
test "a missing history summary times out without moving the durable cursor" {
    var scratch: [64]u8 = undefined;
    var session = try authenticated(&scratch);
    _ = try session.startSync(.legacy, 100, 255, 10);
    _ = try session.receive(.{ .tag = 0x43, .payload = &.{ 110, 0, 0, 0, 1 } }, 20);
    try session.acceptEvent();
    try std.testing.expectError(error.Timeout, session.tick(6020));
    try std.testing.expectEqual(@as(u32, 100), session.batch.?.cursor);
    try std.testing.expectError(error.InvalidState, session.commitBatch());
}
test "initial key installation is impossible on configured rings" {
    var scratch: [64]u8 = undefined;
    var session = try authenticated(&scratch);
    try std.testing.expectError(error.InvalidState, session.installKey(@splat(1), 3));
    try std.testing.expectEqual(State.ready, session.state);
}
test "unconfigured ring installs a key only explicitly and verifies it again" {
    var scratch: [64]u8 = undefined;
    var session = Session.init(&scratch);
    _ = try session.begin(@splat(1), 0);
    const nonce: p.Packet = .{ .tag = 0x2f, .payload = &.{ 0x2c, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 } };
    _ = try session.receive(nonce, 1);
    try std.testing.expect((try session.receive(.{ .tag = 0x2f, .payload = &.{ 0x2e, 2 } }, 2)) == .unconfigured);
    const install = try session.installKey(@splat(1), 3);
    try std.testing.expectEqualSlices(u8, &.{ 0x24, 16 }, install.secret_write[0..2]);
    const challenge = try session.receive(.{ .tag = 0x25, .payload = &.{0} }, 4);
    try std.testing.expectEqualSlices(u8, &.{ 0x2f, 1, 0x2b }, challenge.write);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), session.command[3..19]);
    _ = try session.receive(nonce, 5);
    try std.testing.expect((try session.receive(.{ .tag = 0x2f, .payload = &.{ 0x2e, 0 } }, 6)) == .ready);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), &session.key);
    session.close();
}
