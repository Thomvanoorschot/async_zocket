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
    TlsConnectionClosed,
};

pub const TlsClient = struct {
    allocator: std.mem.Allocator,
    ssl_ctx: *c.SSL_CTX,
    ssl: *c.SSL,
    bio_read: *c.BIO,
    bio_write: *c.BIO,
    handshake_complete: bool = false,
    hostname: []const u8,

    encrypted_buffer: std.ArrayList(u8),
    decrypted_buffer: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator, hostname: []const u8) !*TlsClient {
        _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);

        const method = c.TLS_client_method();
        const ctx = c.SSL_CTX_new(method) orelse {
            std.log.err("Failed to create SSL context", .{});
            return TlsError.TlsContextFailed;
        };

        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) {
            std.log.warn("Failed to set default verify paths", .{});
        }

        _ = c.SSL_CTX_set_options(ctx, c.SSL_OP_NO_SSLv2 | c.SSL_OP_NO_SSLv3 | c.SSL_OP_NO_COMPRESSION);

        const ssl = c.SSL_new(ctx) orelse {
            c.SSL_CTX_free(ctx);
            return TlsError.TlsConnectionFailed;
        };

        const hostname_z = try allocator.dupeZ(u8, hostname);
        defer allocator.free(hostname_z);
        if (c.SSL_set_tlsext_host_name(ssl, hostname_z.ptr) != 1) {
            std.log.warn("Failed to set SNI hostname", .{});
        }

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

    pub fn processIncoming(self: *TlsClient, encrypted_data: []const u8) !?[]const u8 {
        std.log.info("processIncoming: received {} bytes", .{encrypted_data.len});
        if (encrypted_data.len == 0) return null;

        const written = c.BIO_write(self.bio_read, encrypted_data.ptr, @intCast(encrypted_data.len));
        if (written <= 0) {
            std.log.err("Failed to write to BIO", .{});
            return TlsError.TlsReadFailed;
        }
        std.log.info("Wrote {} bytes to BIO_read", .{written});

        if (!self.handshake_complete) {
            std.log.info("Attempting TLS handshake...", .{});
            const handshake_result = c.SSL_do_handshake(self.ssl);
            std.log.info("Handshake result: {}", .{handshake_result});

            if (handshake_result == 1) {
                std.log.info("TLS handshake completed successfully!", .{});
                self.handshake_complete = true;

                const verify_result = c.SSL_get_verify_result(self.ssl);
                if (verify_result != c.X509_V_OK) {
                    std.log.warn("Certificate verification failed: {}", .{verify_result});
                }
            } else {
                const ssl_error = c.SSL_get_error(self.ssl, handshake_result);
                std.log.info("Handshake not complete, SSL error: {}", .{ssl_error});

                if (ssl_error != c.SSL_ERROR_WANT_READ and ssl_error != c.SSL_ERROR_WANT_WRITE) {
                    std.log.err("TLS handshake failed with error: {}", .{ssl_error});
                    return TlsError.TlsHandshakeFailed;
                }
            }
        }

        if (self.handshake_complete) {
            std.log.info("Reading application data after handshake...", .{});
            self.decrypted_buffer.clearRetainingCapacity();
            var temp_buf: [4096]u8 = undefined;

            const bytes_read = c.SSL_read(self.ssl, &temp_buf, temp_buf.len);
            if (bytes_read > 0) {
                std.log.info("Read {} decrypted bytes", .{bytes_read});
                try self.decrypted_buffer.appendSlice(temp_buf[0..@intCast(bytes_read)]);
            } else {
                const ssl_error = c.SSL_get_error(self.ssl, bytes_read);
                std.log.info("SSL_read returned 0, error: {}", .{ssl_error});

                if (ssl_error == c.SSL_ERROR_WANT_READ) {
                    return null;
                } else if (ssl_error == c.SSL_ERROR_WANT_WRITE) {
                    return null;
                } else if (ssl_error == c.SSL_ERROR_ZERO_RETURN) {
                    std.log.info("TLS connection closed cleanly by peer", .{});
                    return TlsError.TlsConnectionClosed;
                } else {
                    std.log.err("SSL_read failed with error: {}", .{ssl_error});
                    return TlsError.TlsReadFailed;
                }
            }

            if (self.decrypted_buffer.items.len > 0) {
                return self.decrypted_buffer.items;
            }
        }

        return null;
    }

    pub fn processOutgoing(self: *TlsClient, plaintext: ?[]const u8) !?[]const u8 {
        if (plaintext) |data| {
            std.log.info("processOutgoing: encrypting {} bytes", .{data.len});
            if (!self.handshake_complete) {
                std.log.warn("Attempt to encrypt data before handshake complete", .{});
                return TlsError.TlsNotReady;
            }

            const bytes_written = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
            if (bytes_written <= 0) {
                const ssl_error = c.SSL_get_error(self.ssl, bytes_written);
                if (ssl_error != c.SSL_ERROR_WANT_READ and ssl_error != c.SSL_ERROR_WANT_WRITE) {
                    std.log.err("SSL_write failed with error: {}", .{ssl_error});
                    return TlsError.TlsWriteFailed;
                }
            } else {
                std.log.info("SSL_write succeeded, wrote {} bytes", .{bytes_written});
            }
        } else {
            std.log.info("processOutgoing: checking for pending encrypted data", .{});
        }

        self.encrypted_buffer.clearRetainingCapacity();
        var temp_buf: [4096]u8 = undefined;
        var total_read: usize = 0;

        while (true) {
            const bytes_read = c.BIO_read(self.bio_write, &temp_buf, temp_buf.len);
            if (bytes_read > 0) {
                std.log.info("Read {} bytes from BIO_write", .{bytes_read});
                try self.encrypted_buffer.appendSlice(temp_buf[0..@intCast(bytes_read)]);
                total_read += @intCast(bytes_read);
            } else {
                std.log.info("No more data to read from BIO_write (total read: {})", .{total_read});
                break;
            }
        }

        if (self.encrypted_buffer.items.len > 0) {
            std.log.info("Returning {} encrypted bytes", .{self.encrypted_buffer.items.len});
            return self.encrypted_buffer.items;
        }

        std.log.info("No encrypted data to send", .{});
        return null;
    }

    pub fn startHandshake(self: *TlsClient) !?[]const u8 {
        c.SSL_set_connect_state(self.ssl);
        const handshake_result = c.SSL_do_handshake(self.ssl);

        if (handshake_result == 1) {
            self.handshake_complete = true;
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
