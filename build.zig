const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const xev = b.dependency("libxev", .{ .target = target, .optimize = optimize });
    lib_mod.addImport("xev", xev.module("xev"));

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "xevzocket",
        .root_module = lib_mod,
    });

    lib_mod.linkLibrary(lib);
}
