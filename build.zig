const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mod = b.addModule("oura", .{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize });
    const lib = b.addLibrary(.{ .name = "oura", .root_module = b.createModule(.{ .root_source_file = b.path("src/abi.zig"), .target = target, .optimize = optimize }), .linkage = .static });
    b.installArtifact(lib);
    lib.installHeader(b.path("include/oura.h"), "oura.h");
    lib.installHeader(b.path("include/module.modulemap"), "module.modulemap");
    const tests = b.addTest(.{ .root_module = mod });
    const test_step = b.step("test", "Test Oura wire vectors, authentication, sync boundaries and C ABI");
    test_step.dependOn(&b.addRunArtifact(tests).step);
    const c_test = b.addExecutable(.{ .name = "oura-abi-test", .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }) });
    c_test.root_module.addCSourceFile(.{ .file = b.path("test/abi.c"), .flags = &.{"-std=c11"} });
    c_test.root_module.addIncludePath(b.path("include"));
    c_test.root_module.linkLibrary(lib);
    test_step.dependOn(&b.addRunArtifact(c_test).step);
    const benchmark = b.addRunArtifact(c_test);
    benchmark.setEnvironmentVariable("OURA_BENCH", "1");
    b.step("bench", "Measure the native C ABI decode boundary").dependOn(&benchmark.step);
    const wasm = b.addExecutable(.{ .name = "oura", .root_module = b.createModule(.{ .root_source_file = b.path("src/abi.zig"), .target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }), .optimize = .ReleaseSmall }) });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    b.step("wasm", "Build the portable Oura protocol module").dependOn(&b.addInstallArtifact(wasm, .{}).step);
}
