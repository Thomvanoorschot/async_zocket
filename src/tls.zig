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
    CertificateVerificationFailed,
};

pub const TlsClient = struct {
    allocator: std.mem.Allocator,
    ssl_ctx: *c.SSL_CTX,
    ssl: *c.SSL,
    bio_read: *c.BIO,
    bio_write: *c.BIO,
    handshake_complete: bool = false,
    hostname: []const u8,

    // Buffers for TLS data
    encrypted_buffer: std.ArrayList(u8),
    decrypted_buffer: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator, hostname: []const u8) !*TlsClient {
        // Initialize OpenSSL library (modern way)
        _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);

        const method = c.TLS_client_method();
        const ctx = c.SSL_CTX_new(method) orelse {
            std.log.err("Failed to create SSL context", .{});
            return TlsError.TlsContextFailed;
        };

        // Set up verification
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) {
            std.log.warn("Failed to set default verify paths", .{});
        }

        // Set security level (optional, for compatibility)
        c.SSL_CTX_set_security_level(ctx, 1);

        const ssl = c.SSL_new(ctx) orelse {
            c.SSL_CTX_free(ctx);
            return TlsError.TlsConnectionFailed;
        };

        // Set hostname for SNI
        const hostname_z = try allocator.dupeZ(u8, hostname);
        defer allocator.free(hostname_z);
        if (c.SSL_set_tlsext_host_name(ssl, hostname_z.ptr) != 1) {
            std.log.warn("Failed to set SNI hostname", .{});
        }

        // Create memory BIOs for non-blocking operation
        const bio_read = c.BIO_new(c.BIO_s_mem()) orelse {
            c.SSL_free(ssl);
            c.SSL_CTX_free(ctx);
            return TlsError.BioFailed;
        };

        const bio_write = c.BIO_new(c.BIO_s_mem()) orelse {
            _ = c.BIO_free(bio_read);
            c.SSL_free(ssl);
            c.SSL_CTX_free(ctx);
            return TlsError.BioFailed;
        };

        c.SSL_set_bio(ssl, bio_read, bio_write);

        const self = try allocator.create(TlsClient);
        self.* = .{
            .allocator = allocator,
            .ssl_ctx = ctx,
            .ssl = ssl,
            .bio_read = bio_read,
            .bio_write = bio_write,
            .hostname = try allocator.dupe(u8, hostname),
            .encrypted_buffer = std.ArrayList(u8).init(allocator),
            .decrypted_buffer = std.ArrayList(u8).init(allocator),
        };

        std.log.info("TLS client initialized for hostname: {s}", .{hostname});
        return self;
    }

    pub fn deinit(self: *TlsClient) void {
        c.SSL_free(self.ssl);
        c.SSL_CTX_free(self.ssl_ctx);
        self.encrypted_buffer.deinit();
        self.decrypted_buffer.deinit();
        self.allocator.free(self.hostname);
        self.allocator.destroy(self);
    }

    /// Process incoming encrypted data and return any decrypted data
    pub fn processIncoming(self: *TlsClient, encrypted_data: []const u8) !?[]const u8 {
        if (encrypted_data.len == 0) return null;

        // Feed encrypted data to SSL
        const written = c.BIO_write(self.bio_read, encrypted_data.ptr, @intCast(encrypted_data.len));
        if (written <= 0) {
            std.log.err("Failed to write to BIO", .{});
            return TlsError.TlsReadFailed;
        }

        if (!self.handshake_complete) {
            const handshake_result = c.SSL_do_handshake(self.ssl);
            if (handshake_result == 1) {
                self.handshake_complete = true;
                std.log.info("TLS handshake completed successfully", .{});

                // Verify certificate
                const verify_result = c.SSL_get_verify_result(self.ssl);
                if (verify_result != c.X509_V_OK) {
                    std.log.warn("Certificate verification failed: {}", .{verify_result});
                    // For now, we'll continue despite verification failure
                    // In production, you might want to fail here
                }
            } else {
                const ssl_error = c.SSL_get_error(self.ssl, handshake_result);
                if (ssl_error != c.SSL_ERROR_WANT_READ and ssl_error != c.SSL_ERROR_WANT_WRITE) {
                    std.log.err("TLS handshake failed with error: {}", .{ssl_error});
                    return TlsError.TlsHandshakeFailed;
                }
                // Handshake needs more data, continue
            }
        }

        if (self.handshake_complete) {
            // Try to read decrypted data
            self.decrypted_buffer.clearRetainingCapacity();
            var temp_buf: [4096]u8 = undefined;

            while (true) {
                const bytes_read = c.SSL_read(self.ssl, &temp_buf, temp_buf.len);
                if (bytes_read > 0) {
                    try self.decrypted_buffer.appendSlice(temp_buf[0..@intCast(bytes_read)]);
                } else {
                    const ssl_error = c.SSL_get_error(self.ssl, bytes_read);
                    if (ssl_error == c.SSL_ERROR_WANT_READ) {
                        break; // No more data available
                    } else if (ssl_error == c.SSL_ERROR_WANT_WRITE) {
                        break; // Need to send data first
                    } else if (ssl_error == c.SSL_ERROR_ZERO_RETURN) {
                        std.log.info("TLS connection closed cleanly", .{});
                        break;
                    } else {
                        std.log.err("SSL_read failed with error: {}", .{ssl_error});
                        return TlsError.TlsReadFailed;
                    }
                }
            }

            if (self.decrypted_buffer.items.len > 0) {
                return self.decrypted_buffer.items;
            }
        }

        return null;
    }

    /// Encrypt data for sending and return any data to send over the socket
    pub fn processOutgoing(self: *TlsClient, plaintext: ?[]const u8) !?[]const u8 {
        if (plaintext) |data| {
            if (!self.handshake_complete) {
                return TlsError.TlsNotReady;
            }

            const bytes_written = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
            if (bytes_written <= 0) {
                const ssl_error = c.SSL_get_error(self.ssl, bytes_written);
                if (ssl_error != c.SSL_ERROR_WANT_READ and ssl_error != c.SSL_ERROR_WANT_WRITE) {
                    std.log.err("SSL_write failed with error: {}", .{ssl_error});
                    return TlsError.TlsWriteFailed;
                }
            }
        }

        // Get any data that needs to be sent over the socket
        self.encrypted_buffer.clearRetainingCapacity();
        var temp_buf: [4096]u8 = undefined;

        while (true) {
            const bytes_read = c.BIO_read(self.bio_write, &temp_buf, temp_buf.len);
            if (bytes_read > 0) {
                try self.encrypted_buffer.appendSlice(temp_buf[0..@intCast(bytes_read)]);
            } else {
                break;
            }
        }

        if (self.encrypted_buffer.items.len > 0) {
            return self.encrypted_buffer.items;
        }

        return null;
    }

    /// Start the handshake process
    pub fn startHandshake(self: *TlsClient) !?[]const u8 {
        c.SSL_set_connect_state(self.ssl);
        const handshake_result = c.SSL_do_handshake(self.ssl);

        if (handshake_result == 1) {
            self.handshake_complete = true;
            std.log.info("TLS handshake completed immediately", .{});
        } else {
            const ssl_error = c.SSL_get_error(self.ssl, handshake_result);
            if (ssl_error != c.SSL_ERROR_WANT_READ and ssl_error != c.SSL_ERROR_WANT_WRITE) {
                std.log.err("TLS handshake start failed with error: {}", .{ssl_error});
                return TlsError.TlsHandshakeFailed;
            }
        }

        return try self.processOutgoing(null);
    }

    pub fn isHandshakeComplete(self: *TlsClient) bool {
        return self.handshake_complete;
    }
};
