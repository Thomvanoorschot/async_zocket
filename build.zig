const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xevzocket_mod = b.addModule("xevzocket", .{
        .root_source_file = b.path("src/root.zig"),
    });

    const xev = b.dependency("libxev", .{ .target = target, .optimize = optimize });
    xevzocket_mod.addImport("xev", xev.module("xev"));

    const xevzocket_lib = b.addStaticLibrary(.{
        .name = "xevzocket",
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(xevzocket_lib);

    xevzocket_mod.linkLibrary(xevzocket_lib);
}
