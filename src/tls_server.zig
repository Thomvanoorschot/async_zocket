const std = @import("std");
const xev = @import("xev");
const tls = @import("tls.zig");

const c = tls.c;
pub const TlsError = tls.TlsError;

const BUFFER_SIZE = tls.BUFFER_SIZE;
const MAX_PATH_LEN = 256;
const MAX_HANDSHAKE_ATTEMPTS = 10;

pub const TlsServer = struct {
    cert_file: []const u8,
    key_file: []const u8,
    ssl_ctx: ?*c.SSL_CTX = null,
    ssl: ?*c.SSL = null,
    bio_read: ?*c.BIO = null,
    bio_write: ?*c.BIO = null,
    handshake_complete: bool = false,

    buffers: tls.TlsBuffers = .{},

    pub fn init(cert_file: []const u8, key_file: []const u8) !TlsServer {
        tls.initOpenSsl();

        return .{
            .cert_file = cert_file,
            .key_file = key_file,
        };
    }

    pub fn initConnection(self: *TlsServer) !void {
        self.cleanup();

        const ctx = try self.createSslContext();
        errdefer c.SSL_CTX_free(ctx);

        const ssl = try tls.createSslInstance(ctx);
        errdefer c.SSL_free(ssl);

        const bio_read = try tls.createBio();
        errdefer _ = c.BIO_free(bio_read);

        const bio_write = try tls.createBio();
        errdefer _ = c.BIO_free(bio_write);

        c.SSL_set_bio(ssl, bio_read, bio_write);
        c.SSL_set_accept_state(ssl);

        self.ssl_ctx = ctx;
        self.ssl = ssl;
        self.bio_read = bio_read;
        self.bio_write = bio_write;
        self.handshake_complete = false;
    }

    pub fn deinit(self: *TlsServer) void {
        self.cleanup();
    }

    pub fn startHandshake(self: *TlsServer) !?[]const u8 {
        if (self.ssl == null) return TlsError.TlsConnectionFailed;
        return null;
    }

    pub fn processIncoming(self: *TlsServer, encrypted_data: []const u8) !?[]const u8 {
        if (encrypted_data.len == 0) return null;
        if (self.ssl == null or self.bio_read == null) return TlsError.TlsConnectionFailed;

        try tls.writeToBio(self.bio_read.?, encrypted_data);

        if (!self.handshake_complete) {
            try self.attemptHandshake();
            if (!self.handshake_complete) return null;
        }

        return try self.readDecryptedData();
    }

    pub fn processOutgoing(self: *TlsServer, plaintext: ?[]const u8) !?[]const u8 {
        if (self.ssl == null) return TlsError.TlsConnectionFailed;

        if (plaintext) |data| {
            try self.writeEncryptedData(data);
        }

        return try self.readFromWriteBio();
    }

    pub fn isHandshakeComplete(self: *TlsServer) bool {
        return self.handshake_complete;
    }

    fn cleanup(self: *TlsServer) void {
        if (self.ssl) |ssl| {
            c.SSL_free(ssl);
            self.ssl = null;
            self.bio_read = null;
            self.bio_write = null;
        }
        if (self.ssl_ctx) |ctx| {
            c.SSL_CTX_free(ctx);
            self.ssl_ctx = null;
        }
    }

    fn createSslContext(self: *TlsServer) !*c.SSL_CTX {
        const method = c.TLS_server_method();
        const ctx = c.SSL_CTX_new(method) orelse {
            std.log.err("Failed to create SSL context", .{});
            return TlsError.TlsContextFailed;
        };

        try self.configureSslContext(ctx);
        try self.loadCertificates(ctx);
        return ctx;
    }

    fn configureSslContext(self: *TlsServer, ctx: *c.SSL_CTX) !void {
        _ = self;

        _ = c.SSL_CTX_set_options(ctx, c.SSL_OP_NO_SSLv2 | c.SSL_OP_NO_SSLv3);
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);
        _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_2_VERSION);

        if (c.SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384") != 1) {
            std.log.warn("Failed to set cipher list", .{});
        }

        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
    }

    fn loadCertificates(self: *TlsServer, ctx: *c.SSL_CTX) !void {
        var cert_path = try self.createNullTerminatedPath(self.cert_file);
        var key_path = try self.createNullTerminatedPath(self.key_file);

        if (c.SSL_CTX_use_certificate_file(ctx, &cert_path, c.SSL_FILETYPE_PEM) <= 0) {
            std.log.err("Failed to load certificate file: {s}", .{cert_path});
            tls.logOpenSslError();
            return TlsError.CertificateLoadFailed;
        }

        if (c.SSL_CTX_use_PrivateKey_file(ctx, &key_path, c.SSL_FILETYPE_PEM) <= 0) {
            std.log.err("Failed to load private key file: {s}", .{key_path});
            tls.logOpenSslError();
            return TlsError.PrivateKeyLoadFailed;
        }

        if (c.SSL_CTX_check_private_key(ctx) != 1) {
            std.log.err("Private key does not match certificate", .{});
            tls.logOpenSslError();
            return TlsError.PrivateKeyLoadFailed;
        }
    }

    fn createNullTerminatedPath(self: *TlsServer, path: []const u8) ![MAX_PATH_LEN:0]u8 {
        _ = self;
        if (path.len >= MAX_PATH_LEN) return TlsError.CertificateLoadFailed;

        var result: [MAX_PATH_LEN:0]u8 = undefined;
        @memcpy(result[0..path.len], path);
        result[path.len] = 0;
        return result;
    }

    fn attemptHandshake(self: *TlsServer) !void {
        const handshake_result = c.SSL_do_handshake(self.ssl.?);

        if (handshake_result == 1) {
            self.handshake_complete = true;
            return;
        }

        const ssl_error = c.SSL_get_error(self.ssl.?, handshake_result);

        switch (ssl_error) {
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {},
            else => {
                std.log.err("Handshake failed with error: {}", .{ssl_error});
                tls.logDetailedSslError(self.ssl.?);
                return TlsError.TlsHandshakeFailed;
            },
        }
    }

    fn readDecryptedData(self: *TlsServer) !?[]const u8 {
        self.buffers.resetDecrypted();
        var temp_buf: [BUFFER_SIZE]u8 = undefined;

        const bytes_read = c.SSL_read(self.ssl.?, &temp_buf, temp_buf.len);

        if (bytes_read > 0) {
            const read_size = @as(usize, @intCast(bytes_read));
            if (read_size > self.buffers.decrypted_buffer.len) return TlsError.TlsReadFailed;

            @memcpy(self.buffers.decrypted_buffer[0..read_size], temp_buf[0..read_size]);
            self.buffers.decrypted_len = read_size;
            return self.buffers.getDecryptedSlice();
        }

        return try tls.handleSslReadError(self.ssl.?, bytes_read);
    }

    fn writeEncryptedData(self: *TlsServer, data: []const u8) !void {
        if (!self.handshake_complete) return TlsError.TlsNotReady;

        const bytes_written = c.SSL_write(self.ssl.?, data.ptr, @intCast(data.len));
        if (bytes_written > 0) return;

        const ssl_error = c.SSL_get_error(self.ssl.?, bytes_written);
        if (ssl_error == c.SSL_ERROR_WANT_READ or ssl_error == c.SSL_ERROR_WANT_WRITE) return;

        std.log.err("SSL_write failed with error: {}", .{ssl_error});
        tls.logDetailedSslError(self.ssl.?);
        return TlsError.TlsWriteFailed;
    }

    fn readFromWriteBio(self: *TlsServer) !?[]const u8 {
        self.buffers.resetEncrypted();
        const encrypted_len = try tls.readFromBio(self.bio_write.?, &self.buffers.encrypted_buffer);
        self.buffers.encrypted_len = encrypted_len;

        return if (self.buffers.encrypted_len > 0) self.buffers.getEncryptedSlice() else null;
    }
};
