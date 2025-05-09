const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xev = b.dependency("libxev", .{ .target = target, .optimize = optimize });
    const jolt_mod = b.addModule("jolt", .{
        .root_source_file = b.path("src/root.zig"),
    });

    jolt_mod.addImport("xev", xev.module("xev"));
}