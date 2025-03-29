const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xev = b.dependency("libxev", .{ .target = target, .optimize = optimize });
    const xevzocket_mod = b.addModule("xevzocket", .{
        .root_source_file = b.path("src/root.zig"),
    });

    xevzocket_mod.addImport("xev", xev.module("xev"));
}