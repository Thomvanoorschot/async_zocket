const std = @import("std");
const xev = @import("xev");

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/x509v3.h");
});

pub const TlsError = error{
    TlsContextFailed,
    TlsConnectionFailed,
    BioFailed,
    TlsHandshakeFailed,
    TlsReadFailed,
    TlsWriteFailed,
    TlsNotReady,
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    TlsConnectionClosed,
};

const BUFFER_SIZE = 4096;
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

    encrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    encrypted_len: usize = 0,
    decrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    decrypted_len: usize = 0,

    pub fn init(cert_file: []const u8, key_file: []const u8) !TlsServer {
        _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);

        return .{
            .cert_file = cert_file,
            .key_file = key_file,
        };
    }

    pub fn initConnection(self: *TlsServer) !void {
        std.log.info("Creating fresh SSL context and connection", .{});

        self.cleanup();

        const ctx = try self.createSslContext();
        errdefer c.SSL_CTX_free(ctx);

        const ssl = try self.createSslInstance(ctx);
        errdefer c.SSL_free(ssl);

        const bio_read = try self.createBio();
        errdefer _ = c.BIO_free(bio_read);

        const bio_write = try self.createBio();
        errdefer _ = c.BIO_free(bio_write);

        c.SSL_set_bio(ssl, bio_read, bio_write);
        c.SSL_set_accept_state(ssl);

        self.ssl_ctx = ctx;
        self.ssl = ssl;
        self.bio_read = bio_read;
        self.bio_write = bio_write;
        self.handshake_complete = false;

        std.log.info("SSL context and connection created successfully", .{});
    }

    pub fn deinit(self: *TlsServer) void {
        self.cleanup();
    }

    pub fn startHandshake(self: *TlsServer) !?[]const u8 {
        if (self.ssl == null) return TlsError.TlsConnectionFailed;

        std.log.info("Handshake initialization complete, waiting for client data", .{});
        return null;
    }

    pub fn processIncoming(self: *TlsServer, encrypted_data: []const u8) !?[]const u8 {
        if (encrypted_data.len == 0) return null;
        if (self.ssl == null or self.bio_read == null) return TlsError.TlsConnectionFailed;

        std.log.info("Processing {} incoming bytes", .{encrypted_data.len});

        try self.writeToReadBio(encrypted_data);

        if (!self.handshake_complete) {
            try self.attemptHandshake();
            if (!self.handshake_complete) return null;
            std.log.info("🎉 TLS handshake completed!", .{});
        }

        return try self.readDecryptedData();
    }

    pub fn processOutgoing(self: *TlsServer, plaintext: ?[]const u8) !?[]const u8 {
        if (self.ssl == null) return TlsError.TlsConnectionFailed;

        if (plaintext) |data| {
            std.log.info("Encrypting {} bytes", .{data.len});
            try self.writeEncryptedData(data);
        }

        return try self.readFromWriteBio();
    }

    pub fn isHandshakeComplete(self: *TlsServer) bool {
        return self.handshake_complete;
    }

    // Private helper methods

    fn cleanup(self: *TlsServer) void {
        if (self.ssl) |ssl| {
            c.SSL_free(ssl);
            self.ssl = null;
            self.bio_read = null; // SSL_free also frees BIOs
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

        std.log.info("SSL context created successfully", .{});
        return ctx;
    }

    fn configureSslContext(self: *TlsServer, ctx: *c.SSL_CTX) !void {
        _ = self;

        // Set security options
        _ = c.SSL_CTX_set_options(ctx, c.SSL_OP_NO_SSLv2 | c.SSL_OP_NO_SSLv3);
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);
        _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_2_VERSION);

        // Set cipher suite
        if (c.SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384") != 1) {
            std.log.warn("Failed to set cipher list", .{});
        }

        // Disable verification for testing
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
    }

    fn loadCertificates(self: *TlsServer, ctx: *c.SSL_CTX) !void {
        var cert_path = try self.createNullTerminatedPath(self.cert_file);
        var key_path = try self.createNullTerminatedPath(self.key_file);

        // Load certificate
        if (c.SSL_CTX_use_certificate_file(ctx, &cert_path, c.SSL_FILETYPE_PEM) <= 0) {
            std.log.err("Failed to load certificate file: {s}", .{self.cert_file});
            logOpenSslError();
            return TlsError.CertificateLoadFailed;
        }

        // Load private key
        if (c.SSL_CTX_use_PrivateKey_file(ctx, &key_path, c.SSL_FILETYPE_PEM) <= 0) {
            std.log.err("Failed to load private key file: {s}", .{self.key_file});
            logOpenSslError();
            return TlsError.PrivateKeyLoadFailed;
        }

        // Verify key matches certificate
        if (c.SSL_CTX_check_private_key(ctx) != 1) {
            std.log.err("Private key does not match certificate", .{});
            logOpenSslError();
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

    fn createSslInstance(self: *TlsServer, ctx: *c.SSL_CTX) !*c.SSL {
        _ = self;
        return c.SSL_new(ctx) orelse {
            std.log.err("Failed to create SSL instance", .{});
            return TlsError.TlsConnectionFailed;
        };
    }

    fn createBio(self: *TlsServer) !*c.BIO {
        _ = self;
        return c.BIO_new(c.BIO_s_mem()) orelse {
            std.log.err("Failed to create BIO", .{});
            return TlsError.BioFailed;
        };
    }

    fn writeToReadBio(self: *TlsServer, data: []const u8) !void {
        const written = c.BIO_write(self.bio_read.?, data.ptr, @intCast(data.len));
        if (written <= 0) {
            std.log.err("Failed to write to read BIO", .{});
            return TlsError.TlsReadFailed;
        }
    }

    fn attemptHandshake(self: *TlsServer) !void {
        const handshake_result = c.SSL_do_handshake(self.ssl.?);

        if (handshake_result == 1) {
            self.handshake_complete = true;
            return;
        }

        const ssl_error = c.SSL_get_error(self.ssl.?, handshake_result);

        switch (ssl_error) {
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {
                std.log.info("Handshake in progress (error: {})", .{ssl_error});
            },
            else => {
                std.log.err("Handshake failed with error: {}", .{ssl_error});
                self.logDetailedSslError();
                return TlsError.TlsHandshakeFailed;
            },
        }
    }

    fn readDecryptedData(self: *TlsServer) !?[]const u8 {
        self.decrypted_len = 0;
        var temp_buf: [BUFFER_SIZE]u8 = undefined;

        const bytes_read = c.SSL_read(self.ssl.?, &temp_buf, temp_buf.len);

        if (bytes_read > 0) {
            const read_size = @as(usize, @intCast(bytes_read));
            if (read_size > self.decrypted_buffer.len) return TlsError.TlsReadFailed;

            @memcpy(self.decrypted_buffer[0..read_size], temp_buf[0..read_size]);
            self.decrypted_len = read_size;
            return self.decrypted_buffer[0..self.decrypted_len];
        }

        return try self.handleSslReadError(bytes_read);
    }

    fn handleSslReadError(self: *TlsServer, bytes_read: c_int) !?[]const u8 {
        const ssl_error = c.SSL_get_error(self.ssl.?, bytes_read);

        return switch (ssl_error) {
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => null,
            c.SSL_ERROR_ZERO_RETURN => TlsError.TlsConnectionClosed,
            else => {
                std.log.err("SSL_read failed with error: {}", .{ssl_error});
                self.logDetailedSslError();
                return TlsError.TlsReadFailed;
            },
        };
    }

    fn writeEncryptedData(self: *TlsServer, data: []const u8) !void {
        if (!self.handshake_complete) return TlsError.TlsNotReady;

        const bytes_written = c.SSL_write(self.ssl.?, data.ptr, @intCast(data.len));
        if (bytes_written > 0) return;

        const ssl_error = c.SSL_get_error(self.ssl.?, bytes_written);
        if (ssl_error == c.SSL_ERROR_WANT_READ or ssl_error == c.SSL_ERROR_WANT_WRITE) return;

        std.log.err("SSL_write failed with error: {}", .{ssl_error});
        self.logDetailedSslError();
        return TlsError.TlsWriteFailed;
    }

    fn readFromWriteBio(self: *TlsServer) !?[]const u8 {
        self.encrypted_len = 0;
        var temp_buf: [BUFFER_SIZE]u8 = undefined;

        while (self.encrypted_len < self.encrypted_buffer.len) {
            const remaining = self.encrypted_buffer.len - self.encrypted_len;
            const read_size = @min(temp_buf.len, remaining);

            const bytes_read = c.BIO_read(self.bio_write.?, &temp_buf, @intCast(read_size));
            if (bytes_read <= 0) break;

            const actual_read = @as(usize, @intCast(bytes_read));
            @memcpy(self.encrypted_buffer[self.encrypted_len .. self.encrypted_len + actual_read], temp_buf[0..actual_read]);
            self.encrypted_len += actual_read;
        }

        return if (self.encrypted_len > 0) self.encrypted_buffer[0..self.encrypted_len] else null;
    }

    fn logDetailedSslError(self: *TlsServer) void {
        if (self.ssl == null) return;

        std.log.err("=== SSL Error Details ===", .{});

        // Log error queue
        var error_count: u32 = 0;
        while (true) {
            const err_code = c.ERR_get_error();
            if (err_code == 0) break;

            var err_buf: [256]u8 = undefined;
            _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
            std.log.err("Error {}: {s}", .{ error_count, std.mem.sliceTo(&err_buf, 0) });
            error_count += 1;
        }

        if (error_count == 0) {
            std.log.err("No errors in OpenSSL queue", .{});
        }

        // Log SSL state
        const state = c.SSL_get_state(self.ssl.?);
        const state_string = c.SSL_state_string_long(self.ssl.?);
        std.log.err("SSL State: {} ({s})", .{ state, @as([*:0]const u8, @ptrCast(state_string)) });

        std.log.err("=== End SSL Error Details ===", .{});
    }
};

fn logOpenSslError() void {
    const err_code = c.ERR_get_error();
    if (err_code == 0) return;

    var err_buf: [256]u8 = undefined;
    _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
    std.log.err("OpenSSL error: {s}", .{std.mem.sliceTo(&err_buf, 0)});
}
