const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xev_dev = b.dependency("libxev", .{ .target = target, .optimize = optimize });

    const boringssl_dep = b.dependency("boringssl", .{});

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var crypto_sources = std.ArrayList([]const u8).init(arena.allocator());

    const full_path = boringssl_dep.path("crypto/aes").getPath(b);
    try glob_sources(arena.allocator(), full_path, ".cc", &crypto_sources);

    const boringssl_crypto = buildBoringCrypto(
        b,
        target,
        optimize,
        boringssl_dep,
    );
    const boringssl_ssl = buildBoringSSLSSL(
        b,
        target,
        optimize,
        boringssl_dep,
        boringssl_crypto,
    );

    const async_zocket_mod = b.addModule("async_zocket", .{
        .root_source_file = b.path("src/root.zig"),
    });

    async_zocket_mod.addImport("xev", xev_dev.module("xev"));
    async_zocket_mod.addIncludePath(boringssl_dep.path("include"));

    const tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    tests.root_module.addImport("xev", xev_dev.module("xev"));
    tests.addIncludePath(b.path("deps/boringssl/include"));
    tests.linkLibCpp();
    tests.linkLibrary(boringssl_crypto);
    tests.linkLibrary(boringssl_ssl);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}

fn buildBoringCrypto(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    boringssl_dep: *std.Build.Dependency,
) *std.Build.Step.Compile {
    const crypto = b.addStaticLibrary(.{
        .name = "crypto",
        .target = target,
        .optimize = optimize,
    });

    crypto.linkLibCpp();
    crypto.addIncludePath(boringssl_dep.path("include"));
    crypto.addIncludePath(boringssl_dep.path("src/include"));

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var crypto_sources = std.ArrayList([]const u8).init(arena.allocator());

    const crypto_dirs = [_][]const u8{
        "crypto/asn1",
        "crypto/base64",
        "crypto/bio",
        "crypto/blake2",
        "crypto/bn_extra",
        "crypto/buf",
        "crypto/bytestring",
        "crypto/chacha",
        "crypto/cipher_extra",
        "crypto/conf",
        "crypto/curve25519",
        "crypto/des",
        "crypto/dh_extra",
        "crypto/digest_extra",
        "crypto/dilithium",
        "crypto/dsa",
        "crypto/ec_extra",
        "crypto/ecdh_extra",
        "crypto/ecdsa_extra",
        "crypto/engine",
        "crypto/err",
        "crypto/evp",
        "crypto/fipsmodule",
        "crypto/hmac_extra",
        "crypto/hpke",
        "crypto/hrss",
        "crypto/keccak",
        "crypto/kyber",
        "crypto/lhash",
        "crypto/md4",
        "crypto/md5",
        "crypto/mldsa",
        "crypto/mlkem",
        "crypto/obj",
        "crypto/pem",
        "crypto/pkcs7",
        "crypto/pkcs8",
        "crypto/poly1305",
        "crypto/pool",
        "crypto/rand_extra",
        "crypto/rc4",
        "crypto/rsa_extra",
        "crypto/sha",
        "crypto/siphash",
        "crypto/slhdsa",
        "crypto/spx",
        "crypto/stack",
        "crypto/trust_token",
        "crypto/x509",
    };

    const boringssl_root = boringssl_dep.path(".").getPath(b);

    for (crypto_dirs) |dir| {
        const full_dir_path = boringssl_dep.path(dir).getPath(b);
        glob_sources_relative(arena.allocator(), full_dir_path, boringssl_root, ".cc", &crypto_sources) catch continue;
    }

    crypto.addCSourceFiles(.{
        .root = boringssl_dep.path("."),
        .files = crypto_sources.items,
        .flags = &[_][]const u8{
            "-Wall",
            "-Werror",
            "-Wformat=2",
            "-Wsign-compare",
            "-Wmissing-field-initializers",
            "-Wwrite-strings",
            "-DOPENSSL_NO_ASM",
        },
    });

    b.installArtifact(crypto);
    return crypto;
}

fn buildBoringSSLSSL(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    boringssl_dep: *std.Build.Dependency,
    crypto: *std.Build.Step.Compile,
) *std.Build.Step.Compile {
    const ssl = b.addStaticLibrary(.{
        .name = "ssl",
        .target = target,
        .optimize = optimize,
    });

    ssl.linkLibCpp();
    ssl.linkLibrary(crypto);
    ssl.addIncludePath(boringssl_dep.path("include"));
    ssl.addIncludePath(boringssl_dep.path("src/include"));

    const ssl_files = [_][]const u8{
        "bio_ssl.cc",
        "d1_both.cc",
        "d1_lib.cc",
        "d1_pkt.cc",
        "d1_srtp.cc",
        "dtls_method.cc",
        "dtls_record.cc",
        "encrypted_client_hello.cc",
        "extensions.cc",
        "handoff.cc",
        "handshake_client.cc",
        "handshake_server.cc",
        "handshake.cc",
        "s3_both.cc",
        "s3_lib.cc",
        "s3_pkt.cc",
        "ssl_aead_ctx.cc",
        "ssl_asn1.cc",
        "ssl_buffer.cc",
        "ssl_cert.cc",
        "ssl_cipher.cc",
        "ssl_credential.cc",
        "ssl_file.cc",
        "ssl_key_share.cc",
        "ssl_lib.cc",
        "ssl_privkey.cc",
        "ssl_session.cc",
        "ssl_stat.cc",
        "ssl_transcript.cc",
        "ssl_versions.cc",
        "ssl_x509.cc",
        "t1_enc.cc",
        "tls_method.cc",
        "tls_record.cc",
        "tls13_both.cc",
        "tls13_client.cc",
        "tls13_enc.cc",
        "tls13_server.cc",
    };

    ssl.addCSourceFiles(.{
        .root = boringssl_dep.path("ssl"),
        .files = &ssl_files,
        .flags = &[_][]const u8{
            "-Wall",
            "-Werror",
            "-DOPENSSL_NO_ASM",
        },
    });

    b.installArtifact(ssl);
    return ssl;
}

pub fn glob_sources(
    allocator: std.mem.Allocator,
    base: []const u8,
    ext: []const u8,
    paths: *std.ArrayList([]const u8),
) !void {
    var dir = try std.fs.cwd().openDir(base, .{ .iterate = true });
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        const path_ext = std.fs.path.extension(entry.path);
        if (std.mem.eql(u8, path_ext, ext)) {
            const path = try std.fs.path.join(allocator, &.{ base, entry.path });
            try paths.append(path);
        }
    }
}

pub fn glob_sources_relative(
    allocator: std.mem.Allocator,
    search_dir: []const u8,
    root_dir: []const u8,
    ext: []const u8,
    paths: *std.ArrayList([]const u8),
) !void {
    var dir = try std.fs.cwd().openDir(search_dir, .{ .iterate = true });
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        const path_ext = std.fs.path.extension(entry.path);
        if (std.mem.eql(u8, path_ext, ext)) {
            if (shouldSkipFile(entry.path)) {
                continue;
            }

            const absolute_path = try std.fs.path.join(allocator, &.{ search_dir, entry.path });
            const relative_path = try std.fs.path.relative(allocator, root_dir, absolute_path);
            try paths.append(relative_path);
        }
    }
}

fn shouldSkipFile(file_path: []const u8) bool {
    const filename = std.fs.path.basename(file_path);

    if (std.mem.endsWith(u8, filename, "_test.cc")) return true;
    if (std.mem.endsWith(u8, filename, "_test.c")) return true;
    if (std.mem.endsWith(u8, filename, "test.cc")) return true;
    if (std.mem.endsWith(u8, filename, "test.c")) return true;

    if (std.mem.eql(u8, filename, "gtest_main.cc")) return true;
    if (std.mem.eql(u8, filename, "file_test_gtest.cc")) return true;

    if (std.mem.indexOf(u8, file_path, "/test/") != null) return true;
    if (std.mem.indexOf(u8, file_path, "\\test\\") != null) return true;

    return false;
}
