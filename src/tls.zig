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

const BUFFER_SIZE = 4096;

pub const TlsClient = struct {
    ssl_ctx: *c.SSL_CTX,
    ssl: *c.SSL,
    bio_read: *c.BIO,
    bio_write: *c.BIO,
    handshake_complete: bool = false,
    hostname: []const u8,

    encrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    encrypted_len: usize = 0,
    decrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    decrypted_len: usize = 0,

    pub fn init(hostname: []const u8) !TlsClient {
        _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);

        const ctx = try createSslContext();
        const ssl = createSslConnection(ctx) catch |err| {
            c.SSL_CTX_free(ctx);
            return err;
        };

        setSniHostname(ssl, hostname) catch |err| {
            c.SSL_free(ssl);
            c.SSL_CTX_free(ctx);
            return err;
        };

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

        return .{
            .ssl_ctx = ctx,
            .ssl = ssl,
            .bio_read = bio_read,
            .bio_write = bio_write,
            .hostname = hostname,
            .encrypted_len = 0,
            .decrypted_len = 0,
        };
    }

    fn createSslContext() !*c.SSL_CTX {
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
        return ctx;
    }

    fn createSslConnection(ctx: *c.SSL_CTX) !*c.SSL {
        const ssl = c.SSL_new(ctx) orelse {
            return TlsError.TlsConnectionFailed;
        };
        return ssl;
    }

    fn setSniHostname(ssl: *c.SSL, hostname: []const u8) !void {
        var hostname_buf: [256]u8 = undefined;
        if (hostname.len >= hostname_buf.len) {
            std.log.warn("Hostname too long for SNI", .{});
            return;
        }

        @memcpy(hostname_buf[0..hostname.len], hostname);
        hostname_buf[hostname.len] = 0;

        if (c.SSL_set_tlsext_host_name(ssl, hostname_buf[0..hostname.len :0].ptr) != 1) {
            std.log.warn("Failed to set SNI hostname", .{});
        }
    }

    pub fn deinit(self: *TlsClient) void {
        c.SSL_free(self.ssl);
        c.SSL_CTX_free(self.ssl_ctx);
    }

    pub fn processIncoming(self: *TlsClient, encrypted_data: []const u8) !?[]const u8 {
        if (encrypted_data.len == 0) return null;

        const written = c.BIO_write(self.bio_read, encrypted_data.ptr, @intCast(encrypted_data.len));
        if (written <= 0) {
            std.log.err("Failed to write to BIO", .{});
            return TlsError.TlsReadFailed;
        }

        if (!self.handshake_complete) {
            try self.performHandshake();
        }

        if (!self.handshake_complete) return null;

        return try self.readDecryptedData();
    }

    fn performHandshake(self: *TlsClient) !void {
        const handshake_result = c.SSL_do_handshake(self.ssl);

        if (handshake_result == 1) {
            self.handshake_complete = true;
            self.verifyCertificate();
            return;
        }

        const ssl_error = c.SSL_get_error(self.ssl, handshake_result);
        if (ssl_error == c.SSL_ERROR_WANT_READ or ssl_error == c.SSL_ERROR_WANT_WRITE) {
            return; // Need more data
        }

        std.log.err("TLS handshake failed with error: {}", .{ssl_error});
        return TlsError.TlsHandshakeFailed;
    }

    fn verifyCertificate(self: *TlsClient) void {
        const verify_result = c.SSL_get_verify_result(self.ssl);
        if (verify_result != c.X509_V_OK) {
            std.log.warn("Certificate verification failed: {}", .{verify_result});
        }
    }

    fn readDecryptedData(self: *TlsClient) !?[]const u8 {
        self.decrypted_len = 0;
        var temp_buf: [BUFFER_SIZE]u8 = undefined;

        const bytes_read = c.SSL_read(self.ssl, &temp_buf, temp_buf.len);
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

    fn handleSslReadError(self: *TlsClient, bytes_read: c_int) !?[]const u8 {
        const ssl_error = c.SSL_get_error(self.ssl, bytes_read);

        self.logOpenSslError();

        switch (ssl_error) {
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => return null,
            c.SSL_ERROR_ZERO_RETURN => return TlsError.TlsConnectionClosed,
            else => {
                std.log.err("SSL_read failed with error: {}", .{ssl_error});
                return TlsError.TlsReadFailed;
            },
        }
    }

    fn logOpenSslError(self: *TlsClient) void {
        _ = self;
        const err_code = c.ERR_get_error();
        if (err_code == 0) return;

        var err_buf: [256]u8 = undefined;
        _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
        std.log.err("OpenSSL error: {s}", .{std.mem.sliceTo(&err_buf, 0)});
    }

    pub fn processOutgoing(self: *TlsClient, plaintext: ?[]const u8) !?[]const u8 {
        if (plaintext) |data| {
            try self.writeEncryptedData(data);
        }

        return self.readFromWriteBio();
    }

    fn writeEncryptedData(self: *TlsClient, data: []const u8) !void {
        if (!self.handshake_complete) {
            std.log.warn("Attempt to encrypt data before handshake complete", .{});
            return TlsError.TlsNotReady;
        }

        const bytes_written = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (bytes_written > 0) return;

        const ssl_error = c.SSL_get_error(self.ssl, bytes_written);
        if (ssl_error == c.SSL_ERROR_WANT_READ or ssl_error == c.SSL_ERROR_WANT_WRITE) {
            return; // Acceptable, will retry
        }

        std.log.err("SSL_write failed with error: {}", .{ssl_error});
        return TlsError.TlsWriteFailed;
    }

    fn readFromWriteBio(self: *TlsClient) !?[]const u8 {
        self.encrypted_len = 0;
        var temp_buf: [BUFFER_SIZE]u8 = undefined;

        while (self.encrypted_len < self.encrypted_buffer.len) {
            const remaining = self.encrypted_buffer.len - self.encrypted_len;
            const read_size = @min(temp_buf.len, remaining);

            const bytes_read = c.BIO_read(self.bio_write, &temp_buf, @intCast(read_size));
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
