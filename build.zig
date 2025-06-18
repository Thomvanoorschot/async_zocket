const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xev_dep = b.dependency("libxev", .{ .target = target, .optimize = optimize });
    const boring_tls_dep = b.dependency("boring_tls", .{ .target = target, .optimize = optimize });

    const async_zocket_mod = b.addModule("async_zocket", .{
        .link_libcpp = true,
        .root_source_file = b.path("src/root.zig"),
    });

    async_zocket_mod.addImport("xev", xev_dep.module("xev"));
    async_zocket_mod.addImport("boring_tls", boring_tls_dep.module("boring_tls"));

    const tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    tests.root_module.addImport("xev", xev_dep.module("xev"));
    tests.root_module.addImport("boring_tls", boring_tls_dep.module("boring_tls"));

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
