const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xev = b.dependency("libxev", .{ .target = target, .optimize = optimize });
    const jolt_mod = b.addModule("jolt", .{
        .root_source_file = b.path("src/root.zig"),
    });

    jolt_mod.addImport("xev", xev.module("xev"));

    // Add test step
    const tests = b.addTest(.{
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .optimize = optimize,
    });

    tests.root_module.addImport("xev", xev.module("xev"));

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
