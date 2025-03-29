const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xevzocket_mod = b.addModule("xevzocket", .{
        .root_source_file = b.path("src/root.zig"),
    });

    const xev = b.dependency("libxev", .{ .target = target, .optimize = optimize });

    const xevzocket_lib = try buildLibxevzocket(b, .{
        .target = target,
        .optimize = optimize,
    });
    xevzocket_mod.addImport("xev", xev.module("xev"));
    xevzocket_mod.linkLibrary(xevzocket_lib);
}

const LibOptions = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Mode,
};
fn buildLibxevzocket(b: *std.Build, options: LibOptions) !*std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{
        .name = "xevzocket",
        .target = options.target,
        .optimize = options.optimize,
        .link_libc = true,
    });
    b.installArtifact(lib);

    return lib;
}
