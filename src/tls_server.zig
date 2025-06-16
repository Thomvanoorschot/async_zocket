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

fn logGlobalOpenSslError() void {
    const err_code = c.ERR_get_error();
    if (err_code == 0) return;

    var err_buf: [256]u8 = undefined;
    _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
    std.log.err("OpenSSL error: {s}", .{std.mem.sliceTo(&err_buf, 0)});
}

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
            .encrypted_len = 0,
            .decrypted_len = 0,
        };
    }

    pub fn initConnection(self: *TlsServer) !void {
        std.log.info("Creating completely fresh SSL context and connection", .{});

        // Clean up any existing connection and context
        if (self.ssl) |ssl| {
            c.SSL_free(ssl);
            self.ssl = null;
        }
        if (self.ssl_ctx) |ctx| {
            c.SSL_CTX_free(ctx);
            self.ssl_ctx = null;
        }

        // Create completely fresh SSL context for this connection
        const ctx = try createSslContext(self.cert_file, self.key_file);
        self.ssl_ctx = ctx;

        // Create fresh SSL instance
        const ssl = c.SSL_new(ctx) orelse {
            std.log.err("Failed to create SSL instance", .{});
            c.SSL_CTX_free(ctx);
            self.ssl_ctx = null;
            return TlsError.TlsConnectionFailed;
        };

        // Create fresh BIOs
        const bio_read = c.BIO_new(c.BIO_s_mem()) orelse {
            std.log.err("Failed to create read BIO", .{});
            c.SSL_free(ssl);
            c.SSL_CTX_free(ctx);
            self.ssl_ctx = null;
            return TlsError.BioFailed;
        };

        const bio_write = c.BIO_new(c.BIO_s_mem()) orelse {
            std.log.err("Failed to create write BIO", .{});
            _ = c.BIO_free(bio_read);
            c.SSL_free(ssl);
            c.SSL_CTX_free(ctx);
            self.ssl_ctx = null;
            return TlsError.BioFailed;
        };

        // Associate BIOs with SSL
        c.SSL_set_bio(ssl, bio_read, bio_write);

        // Set server mode
        c.SSL_set_accept_state(ssl);

        self.ssl = ssl;
        self.bio_read = bio_read;
        self.bio_write = bio_write;
        self.handshake_complete = false;

        const state_string = c.SSL_state_string_long(ssl);
        std.log.info("Fresh SSL context and connection created, state: {s}", .{@as([*:0]const u8, @ptrCast(state_string))});
    }

    pub fn deinit(self: *TlsServer) void {
        if (self.ssl) |ssl| {
            c.SSL_free(ssl); // This also frees the BIOs
        }
        if (self.ssl_ctx) |ctx| {
            c.SSL_CTX_free(ctx);
        }
    }

    pub fn startHandshake(self: *TlsServer) !?[]const u8 {
        if (self.ssl == null) {
            return TlsError.TlsConnectionFailed;
        }

        const state_string = c.SSL_state_string_long(self.ssl.?);
        std.log.info("Starting handshake, SSL state: {s}", .{@as([*:0]const u8, @ptrCast(state_string))});

        // DON'T call processOutgoing here - let the first client message trigger everything
        std.log.info("Handshake initialization complete, waiting for client data", .{});
        return null;
    }

    pub fn processIncoming(self: *TlsServer, encrypted_data: []const u8) !?[]const u8 {
        if (encrypted_data.len == 0) return null;
        if (self.ssl == null or self.bio_read == null) return TlsError.TlsConnectionFailed;

        std.log.info("TLS processIncoming: {} bytes", .{encrypted_data.len});
        dumpHexData(encrypted_data, "TLS_IN");

        const written = c.BIO_write(self.bio_read.?, encrypted_data.ptr, @intCast(encrypted_data.len));
        if (written <= 0) {
            std.log.err("Failed to write to BIO", .{});
            return TlsError.TlsReadFailed;
        }

        std.log.info("Written {} bytes to BIO", .{written});

        const was_complete = self.handshake_complete;
        if (!self.handshake_complete) {
            std.log.info("Handshake not complete, performing single handshake attempt", .{});

            // Try handshake only ONCE per incoming data batch
            const handshake_result = c.SSL_do_handshake(self.ssl.?);
            std.log.info("SSL_do_handshake returned: {}", .{handshake_result});

            if (handshake_result == 1) {
                self.handshake_complete = true;
                std.log.info("TLS handshake completed successfully", .{});
            } else {
                const ssl_error = c.SSL_get_error(self.ssl.?, handshake_result);
                std.log.info("TLS handshake SSL error: {}", .{ssl_error});
                self.logSslState();

                if (ssl_error == c.SSL_ERROR_WANT_READ) {
                    std.log.info("TLS handshake needs more data (WANT_READ)", .{});
                    // Don't return here - continue to check for outgoing data
                } else if (ssl_error == c.SSL_ERROR_WANT_WRITE) {
                    std.log.info("TLS handshake needs to write data (WANT_WRITE)", .{});
                    // Don't return here - continue to check for outgoing data
                } else {
                    std.log.err("TLS handshake failed with error: {}", .{ssl_error});
                    self.logDetailedSslError();
                    return TlsError.TlsHandshakeFailed;
                }
            }

            std.log.info("After handshake attempt, complete: {}", .{self.handshake_complete});
        }

        // If handshake just completed, log it
        if (!was_complete and self.handshake_complete) {
            std.log.info("🎉 TLS handshake just completed!", .{});
        }

        if (!self.handshake_complete) {
            std.log.info("Handshake still not complete, returning null for application data", .{});
            // Still return null for application data, but we'll check for outgoing handshake data separately
            return null;
        }

        std.log.info("Handshake complete, reading decrypted data", .{});
        return try self.readDecryptedData();
    }

    pub fn processOutgoing(self: *TlsServer, plaintext: ?[]const u8) !?[]const u8 {
        if (self.ssl == null) return TlsError.TlsConnectionFailed;

        if (plaintext) |data| {
            std.log.info("TLS processOutgoing: encrypting {} bytes", .{data.len});
            try self.writeEncryptedData(data);
        } else {
            std.log.info("TLS processOutgoing: checking for pending data", .{});
        }

        const result = try self.readFromWriteBio();
        if (result) |data| {
            std.log.info("TLS processOutgoing: returning {} bytes", .{data.len});
        } else {
            std.log.info("TLS processOutgoing: no outgoing data", .{});
        }
        return result;
    }

    pub fn isHandshakeComplete(self: *TlsServer) bool {
        return self.handshake_complete;
    }

    fn createSslContext(cert_file: []const u8, key_file: []const u8) !*c.SSL_CTX {
        const method = c.TLS_server_method();
        const ctx = c.SSL_CTX_new(method) orelse {
            std.log.err("Failed to create SSL context", .{});
            return TlsError.TlsContextFailed;
        };

        // Set security options
        _ = c.SSL_CTX_set_options(ctx, c.SSL_OP_NO_SSLv2 | c.SSL_OP_NO_SSLv3);

        // Force TLS 1.2 only for now (simpler handshake)
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);
        _ = c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_2_VERSION);

        // Set a specific cipher suite for debugging
        if (c.SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384") != 1) {
            std.log.warn("Failed to set cipher list", .{});
        }

        // Add null terminator for C strings
        var cert_path: [256]u8 = undefined;
        if (cert_file.len >= cert_path.len) {
            std.log.err("Certificate file path too long", .{});
            c.SSL_CTX_free(ctx);
            return TlsError.CertificateLoadFailed;
        }
        @memcpy(cert_path[0..cert_file.len], cert_file);
        cert_path[cert_file.len] = 0;

        var key_path: [256]u8 = undefined;
        if (key_file.len >= key_path.len) {
            std.log.err("Private key file path too long", .{});
            c.SSL_CTX_free(ctx);
            return TlsError.PrivateKeyLoadFailed;
        }
        @memcpy(key_path[0..key_file.len], key_file);
        key_path[key_file.len] = 0;

        // Load certificate
        if (c.SSL_CTX_use_certificate_file(ctx, cert_path[0..cert_file.len :0].ptr, c.SSL_FILETYPE_PEM) <= 0) {
            std.log.err("Failed to load certificate file: {s}", .{cert_file});
            logGlobalOpenSslError();
            c.SSL_CTX_free(ctx);
            return TlsError.CertificateLoadFailed;
        }

        // Load private key
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path[0..key_file.len :0].ptr, c.SSL_FILETYPE_PEM) <= 0) {
            std.log.err("Failed to load private key file: {s}", .{key_file});
            logGlobalOpenSslError();
            c.SSL_CTX_free(ctx);
            return TlsError.PrivateKeyLoadFailed;
        }

        // Verify private key matches certificate
        if (c.SSL_CTX_check_private_key(ctx) != 1) {
            std.log.err("Private key does not match certificate", .{});
            logGlobalOpenSslError();
            c.SSL_CTX_free(ctx);
            return TlsError.PrivateKeyLoadFailed;
        }

        // Disable verification for testing
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);

        std.log.info("SSL context created successfully (TLS 1.2 only)", .{});
        return ctx;
    }

    fn createSslConnection(ctx: *c.SSL_CTX) !*c.SSL {
        const ssl = c.SSL_new(ctx) orelse {
            return TlsError.TlsConnectionFailed;
        };
        return ssl;
    }

    fn performHandshake(self: *TlsServer) !void {
        std.log.info("Performing TLS handshake...", .{});

        // Keep trying the handshake until it succeeds or fails
        var attempts: u8 = 0;
        while (attempts < 10) { // Prevent infinite loops
            const handshake_result = c.SSL_do_handshake(self.ssl.?);
            std.log.info("SSL_do_handshake returned: {} (attempt {})", .{ handshake_result, attempts + 1 });

            if (handshake_result == 1) {
                self.handshake_complete = true;
                std.log.info("TLS handshake completed successfully", .{});
                return;
            }

            const ssl_error = c.SSL_get_error(self.ssl.?, handshake_result);
            std.log.info("TLS handshake in progress, SSL error: {}", .{ssl_error});

            if (ssl_error == c.SSL_ERROR_WANT_READ) {
                std.log.info("TLS handshake needs more data (WANT_READ)", .{});
                // For WANT_READ, we need to wait for more input data
                break;
            } else if (ssl_error == c.SSL_ERROR_WANT_WRITE) {
                std.log.info("TLS handshake needs to write data (WANT_WRITE)", .{});
                // For WANT_WRITE, we should continue trying as OpenSSL has data to send
                attempts += 1;
                continue;
            }

            // Any other error is fatal
            std.log.err("TLS handshake failed with error: {}", .{ssl_error});
            self.logDetailedSslError();
            return TlsError.TlsHandshakeFailed;
        }

        if (attempts >= 10) {
            std.log.err("TLS handshake failed: too many attempts", .{});
            return TlsError.TlsHandshakeFailed;
        }
    }

    fn readDecryptedData(self: *TlsServer) !?[]const u8 {
        self.decrypted_len = 0;
        var temp_buf: [BUFFER_SIZE]u8 = undefined;

        const bytes_read = c.SSL_read(self.ssl.?, &temp_buf, temp_buf.len);
        if (bytes_read > 0) {
            const read_size = @as(usize, @intCast(bytes_read));
            if (read_size > self.decrypted_buffer.len) {
                return TlsError.TlsReadFailed;
            }
            @memcpy(self.decrypted_buffer[0..read_size], temp_buf[0..read_size]);
            self.decrypted_len = read_size;
            return self.decrypted_buffer[0..self.decrypted_len];
        }

        return try self.handleSslReadError(bytes_read);
    }

    fn handleSslReadError(self: *TlsServer, bytes_read: c_int) !?[]const u8 {
        const ssl_error = c.SSL_get_error(self.ssl.?, bytes_read);

        self.logDetailedSslError();

        switch (ssl_error) {
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => return null,
            c.SSL_ERROR_ZERO_RETURN => return TlsError.TlsConnectionClosed,
            else => {
                std.log.err("SSL_read failed with error: {}", .{ssl_error});
                return TlsError.TlsReadFailed;
            },
        }
    }

    fn logDetailedSslError(self: *TlsServer) void {
        if (self.ssl == null) return;

        std.log.err("=== Detailed SSL Error Information ===", .{});

        // Log all errors in the error queue
        var error_count: u32 = 0;
        while (true) {
            const err_code = c.ERR_get_error();
            if (err_code == 0) break;

            var err_buf: [256]u8 = undefined;
            _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
            std.log.err("SSL Error {}: {s}", .{ error_count, std.mem.sliceTo(&err_buf, 0) });
            error_count += 1;
        }

        if (error_count == 0) {
            std.log.err("No errors in OpenSSL error queue", .{});
        }

        // Log SSL connection state
        const state = c.SSL_get_state(self.ssl.?);
        const state_string = c.SSL_state_string_long(self.ssl.?);
        std.log.err("SSL State: {} ({s})", .{ state, @as([*:0]const u8, @ptrCast(state_string)) });

        // Log SSL version info
        const version = c.SSL_version(self.ssl.?);
        std.log.err("SSL Version: {}", .{version});

        std.log.err("=== End SSL Error Information ===", .{});
    }

    fn writeEncryptedData(self: *TlsServer, data: []const u8) !void {
        if (!self.handshake_complete) {
            std.log.warn("Attempt to encrypt data before handshake complete", .{});
            return TlsError.TlsNotReady;
        }

        const bytes_written = c.SSL_write(self.ssl.?, data.ptr, @intCast(data.len));
        if (bytes_written > 0) return;

        const ssl_error = c.SSL_get_error(self.ssl.?, bytes_written);
        if (ssl_error == c.SSL_ERROR_WANT_READ or ssl_error == c.SSL_ERROR_WANT_WRITE) {
            return;
        }

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

        if (self.encrypted_len > 0) {
            return self.encrypted_buffer[0..self.encrypted_len];
        }

        return null;
    }

    fn logSslState(self: *TlsServer) void {
        if (self.ssl == null) return;
        const state = c.SSL_get_state(self.ssl.?);
        const state_string = c.SSL_state_string_long(self.ssl.?);
        if (state_string != null) {
            std.log.info("SSL state: {} ({s})", .{ state, @as([*:0]const u8, @ptrCast(state_string)) });
        } else {
            std.log.info("SSL state: {} (unknown)", .{state});
        }
    }

    fn dumpHexData(data: []const u8, prefix: []const u8) void {
        std.log.info("{s}: {} bytes", .{ prefix, data.len });
        if (data.len > 0) {
            var i: usize = 0;
            while (i < @min(data.len, 32)) { // Show first 32 bytes
                if (i % 16 == 0) {
                    std.debug.print("\n{s}[{x:0>4}]: ", .{ prefix, i });
                }
                std.debug.print("{x:0>2} ", .{data[i]});
                i += 1;
            }
            std.debug.print("\n", .{});
        }
    }
};
