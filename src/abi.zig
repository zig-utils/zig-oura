//! Stable C ABI. Context/scratch/output belong to the host; no hidden allocator.
const std = @import("std");
const core = @import("root.zig");
const Session = core.session.Session;
const Context = struct { session: Session, output: Output = .{}, consumed: usize = 0 };
const Output = extern struct {
    kind: u32 = 0,
    tag: u32 = 0,
    timestamp_ds: u32 = 0,
    count: u32 = 0,
    bytes_left: u32 = 0,
    auxiliary: u32 = 0,
    timestamp_ms: u64 = 0,
    data: ?[*]const u8 = null,
    length: usize = 0,
    value: f64 = 0,
};
pub const Sample = extern struct { kind: u32, index: u32, interval_ms: u32, value: f64 };
fn status(err: anyerror) i32 {
    return switch (err) {
        error.NoSpace => -2,
        error.Unsupported => -3,
        error.AuthenticationFailed, error.InvalidNonce => -4,
        error.Timeout => -5,
        error.InvalidState, error.Closed, error.PendingEvent, error.NoPendingEvent, error.UndrainedInput => -6,
        error.CountMismatch => -7,
        error.MissingSummary, error.IncompleteEnvelope => -8,
        error.Rejected, error.WrongBuffer => -9,
        error.Overflow, error.TooLarge => -10,
        else => -1,
    };
}
fn context(pointer: ?*anyopaque) ?*Context {
    const raw = pointer orelse return null;
    if (@intFromPtr(raw) % @alignOf(Context) != 0) return null;
    return @ptrCast(@alignCast(raw));
}
fn result(ctx: *Context, output: core.session.Output) i32 {
    ctx.output = .{};
    switch (output) {
        .none => {},
        .write => |bytes| ctx.output = .{ .kind = 1, .data = bytes.ptr, .length = bytes.len },
        .secret_write => |bytes| ctx.output = .{ .kind = 1, .auxiliary = 1, .data = bytes.ptr, .length = bytes.len },
        .ready => ctx.output.kind = 2,
        .event => |event| ctx.output = .{ .kind = 3, .tag = event.tag, .timestamp_ds = event.timestamp_ds, .timestamp_ms = event.timestamp_ms, .data = event.body.ptr, .length = event.body.len },
        .batch => |batch| ctx.output = .{ .kind = 4, .count = batch.events, .bytes_left = batch.bytes_left, .timestamp_ds = ctx.session.batch.?.candidate, .auxiliary = batch.sleep_progress },
        .heart_rate => |sample| ctx.output = .{ .kind = 5, .value = @floatFromInt(sample.bpm), .auxiliary = sample.ibi_ms },
        .packet => |packet| ctx.output = .{ .kind = 6, .tag = packet.tag, .data = packet.payload.ptr, .length = packet.payload.len },
        .unsupported => ctx.output.kind = 7,
        .unconfigured => ctx.output.kind = 8,
    }
    return @intCast(ctx.output.kind);
}
export fn oura_abi_version() u32 {
    return 1;
}
export fn oura_context_size() usize {
    return @sizeOf(Context);
}
export fn oura_context_align() usize {
    return @alignOf(Context);
}
export fn oura_context_init(pointer: ?*anyopaque, size: usize, scratch: ?[*]u8, scratch_size: usize) i32 {
    const ctx = context(pointer) orelse return -1;
    if (size < @sizeOf(Context) or scratch == null or scratch_size == 0) return -1;
    ctx.* = .{ .session = Session.init(scratch.?[0..scratch_size]) };
    return 0;
}
export fn oura_begin(pointer: ?*anyopaque, key: ?[*]const u8, key_size: usize, now_ms: u64) i32 {
    const ctx = context(pointer) orelse return -1;
    if (key == null or key_size != 16) return -1;
    return result(ctx, ctx.session.begin(key.?[0..16].*, now_ms) catch |err| return status(err));
}
export fn oura_install_key(pointer: ?*anyopaque, key: ?[*]const u8, length: usize, now_ms: u64) i32 {
    const ctx = context(pointer) orelse return -1;
    if (key == null or length != 16) return -1;
    return result(ctx, ctx.session.installKey(key.?[0..16].*, now_ms) catch |err| return status(err));
}
export fn oura_sync(pointer: ?*anyopaque, extended: u32, cursor: u32, limit: u16, now_ms: u64) i32 {
    const ctx = context(pointer) orelse return -1;
    if (extended > 1) return -1;
    return result(ctx, ctx.session.startSync(if (extended == 1) .extended else .legacy, cursor, limit, now_ms) catch |err| return status(err));
}
/// Parses one packet and reports consumed bytes. Drain/accept its events before
/// calling again for the next coalesced packet or reusing the input memory.
export fn oura_receive(pointer: ?*anyopaque, bytes: ?[*]const u8, length: usize, now_ms: u64) i32 {
    const ctx = context(pointer) orelse return -1;
    if (bytes == null or length == 0) return -1;
    var iterator: core.protocol.Iterator = .{ .bytes = bytes.?[0..length] };
    const packet = (iterator.next() catch |err| {
        ctx.session.close();
        ctx.output = .{};
        return status(err);
    }) orelse return -1;
    ctx.consumed = packet.payload.len + 2;
    return result(ctx, ctx.session.receive(packet, now_ms) catch |err| return status(err));
}
export fn oura_next(pointer: ?*anyopaque) i32 {
    const ctx = context(pointer) orelse return -1;
    return result(ctx, ctx.session.next() catch |err| return status(err));
}
export fn oura_accept(pointer: ?*anyopaque) i32 {
    const ctx = context(pointer) orelse return -1;
    ctx.session.acceptEvent() catch |err| return status(err);
    return 0;
}
export fn oura_commit(pointer: ?*anyopaque, cursor: ?*u32) i32 {
    const ctx = context(pointer) orelse return -1;
    if (cursor == null) return -1;
    cursor.?.* = ctx.session.commitBatch() catch |err| return status(err);
    return 0;
}
export fn oura_tick(pointer: ?*anyopaque, now_ms: u64) i32 {
    const ctx = context(pointer) orelse return -1;
    ctx.session.tick(now_ms) catch |err| return status(err);
    return 0;
}
export fn oura_close(pointer: ?*anyopaque) void {
    const ctx = context(pointer) orelse return;
    std.crypto.secureZero(u8, ctx.session.assembler.scratch);
    ctx.session.close();
    ctx.output = .{};
    ctx.consumed = 0;
}
export fn oura_output(pointer: ?*anyopaque) ?*const Output {
    const ctx = context(pointer) orelse return null;
    return &ctx.output;
}
export fn oura_consumed(pointer: ?*anyopaque) usize {
    const ctx = context(pointer) orelse return 0;
    return ctx.consumed;
}
export fn oura_auth_result(pointer: ?*anyopaque) i32 {
    const ctx = context(pointer) orelse return -1;
    return if (ctx.session.last_auth) |value| @backingInt(value) else -1;
}
export fn oura_key_result(pointer: ?*anyopaque) i32 {
    const ctx = context(pointer) orelse return -1;
    return if (ctx.session.last_key_result) |value| value else -1;
}
export fn oura_decode_samples(tag: u8, body: ?[*]const u8, length: usize, output: ?[*]Sample, capacity: usize) i32 {
    if (body == null or output == null or length > core.events.max_body) return -1;
    var samples: [1024]core.events.Sample = undefined;
    const count = core.events.decode(.{ .tag = tag, .timestamp_ds = 0, .timestamp_ms = 0, .body = body.?[0..length] }, samples[0..@min(samples.len, capacity)]) catch |err| return status(err);
    for (samples[0..count], 0..) |sample, index| output.?[index] = .{ .kind = @backingInt(sample.kind), .index = sample.index, .interval_ms = sample.interval_ms, .value = sample.value };
    return @intCast(count);
}

/// Read/stream controls only. No reset, key replacement, DFU or erase opcode.
export fn oura_request(pointer: ?*anyopaque, operation: u32, argument: u32, value: u32) i32 {
    const ctx = context(pointer) orelse return -1;
    if (ctx.session.state != .idle and ctx.session.state != .ready) return -6;
    if (argument > 255 or value > (if (operation == 9) @as(u32, 65535) else 255)) return -1;
    const feature = if (operation == 5 or operation == 6)
        std.enums.fromInt(core.protocol.Feature, @as(u8, @intCast(argument))) orelse return -3
    else
        core.protocol.Feature.daytime_hr;
    const bytes = switch (operation) {
        1 => core.protocol.firmware(&ctx.session.command),
        2 => core.protocol.battery(&ctx.session.command),
        3 => core.protocol.serial(&ctx.session.command),
        4 => core.protocol.capabilities(@intCast(argument), &ctx.session.command),
        5 => core.protocol.featureLatest(feature, &ctx.session.command),
        6 => core.protocol.featureMode(feature, std.enums.fromInt(core.protocol.FeatureMode, @as(u8, @intCast(value))) orelse return -3, &ctx.session.command),
        7 => core.protocol.subscribe(@intCast(argument), &ctx.session.command),
        8 => core.protocol.hardware(&ctx.session.command),
        9 => core.protocol.eventSubscribe(@intCast(argument), @intCast(value), &ctx.session.command),
        10 => core.protocol.parameter(@intCast(argument), &ctx.session.command),
        11 => core.protocol.statePoll(&ctx.session.command),
        13 => core.protocol.dataFlush(&ctx.session.command),
        else => return -3,
    } catch |err| return status(err);
    return result(ctx, .{ .write = bytes });
}

// A WASM instance owns one independent context. Native hosts use the C ABI's
// caller-allocated contexts and can use many rings on different threads.
var wasm_context: Context = undefined;
var wasm_scratch: [65535]u8 = undefined;
var wasm_input: [8192]u8 = undefined;
var wasm_decode_input: [core.events.max_body]u8 = undefined;
var wasm_samples: [1024]Sample = undefined;
var wasm_cursor: u32 = 0;
export fn oura_wasm_init() *anyopaque {
    _ = oura_context_init(&wasm_context, @sizeOf(Context), &wasm_scratch, wasm_scratch.len);
    return &wasm_context;
}
export fn oura_input_ptr() [*]u8 {
    return &wasm_input;
}
export fn oura_input_capacity() usize {
    return wasm_input.len;
}
export fn oura_decode_input_ptr() [*]u8 {
    return &wasm_decode_input;
}
export fn oura_wasm_commit(pointer: ?*anyopaque) i32 {
    return oura_commit(pointer, &wasm_cursor);
}
export fn oura_wasm_cursor() u32 {
    return wasm_cursor;
}
export fn oura_wasm_decode(tag: u8, length: usize) i32 {
    return oura_decode_samples(tag, &wasm_decode_input, length, &wasm_samples, wasm_samples.len);
}
export fn oura_sample_kind(index: usize) u32 {
    return if (index < wasm_samples.len) wasm_samples[index].kind else 0xffffffff;
}
export fn oura_sample_index(index: usize) u32 {
    return if (index < wasm_samples.len) wasm_samples[index].index else 0;
}
export fn oura_sample_interval(index: usize) u32 {
    return if (index < wasm_samples.len) wasm_samples[index].interval_ms else 0;
}
export fn oura_sample_value(index: usize) f64 {
    return if (index < wasm_samples.len) wasm_samples[index].value else std.math.nan(f64);
}
export fn oura_output_kind(pointer: ?*anyopaque) u32 {
    const ctx = context(pointer) orelse return 0;
    return ctx.output.kind;
}
export fn oura_output_tag(pointer: ?*anyopaque) u32 {
    const ctx = context(pointer) orelse return 0;
    return ctx.output.tag;
}
export fn oura_output_ticks(pointer: ?*anyopaque) u32 {
    const ctx = context(pointer) orelse return 0;
    return ctx.output.timestamp_ds;
}
export fn oura_output_milliseconds(pointer: ?*anyopaque) u64 {
    const ctx = context(pointer) orelse return 0;
    return ctx.output.timestamp_ms;
}
export fn oura_output_data(pointer: ?*anyopaque) ?[*]const u8 {
    const ctx = context(pointer) orelse return null;
    return ctx.output.data;
}
export fn oura_output_length(pointer: ?*anyopaque) usize {
    const ctx = context(pointer) orelse return 0;
    return ctx.output.length;
}
export fn oura_output_count(pointer: ?*anyopaque) u32 {
    const ctx = context(pointer) orelse return 0;
    return ctx.output.count;
}
export fn oura_output_left(pointer: ?*anyopaque) u32 {
    const ctx = context(pointer) orelse return 0;
    return ctx.output.bytes_left;
}
export fn oura_output_auxiliary(pointer: ?*anyopaque) u32 {
    const ctx = context(pointer) orelse return 0;
    return ctx.output.auxiliary;
}
export fn oura_output_value(pointer: ?*anyopaque) f64 {
    const ctx = context(pointer) orelse return std.math.nan(f64);
    return ctx.output.value;
}
