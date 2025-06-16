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
    ssl_ctx: *c.SSL_CTX,
    ssl: *c.SSL,
    bio_read: *c.BIO,
    bio_write: *c.BIO,
    handshake_complete: bool = false,

    encrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    encrypted_len: usize = 0,
    decrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    decrypted_len: usize = 0,

    pub fn init(cert_file: []const u8, key_file: []const u8) !TlsServer {
        _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);

        const ctx = try createSslContext(cert_file, key_file);
        const ssl = createSslConnection(ctx) catch |err| {
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
            .encrypted_len = 0,
            .decrypted_len = 0,
        };
    }

    pub fn deinit(self: *TlsServer) void {
        c.SSL_free(self.ssl);
        c.SSL_CTX_free(self.ssl_ctx);
    }

    pub fn startHandshake(self: *TlsServer) !?[]const u8 {
        c.SSL_set_accept_state(self.ssl);
        return try self.processOutgoing(null);
    }

    pub fn processIncoming(self: *TlsServer, encrypted_data: []const u8) !?[]const u8 {
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

    pub fn processOutgoing(self: *TlsServer, plaintext: ?[]const u8) !?[]const u8 {
        if (plaintext) |data| {
            try self.writeEncryptedData(data);
        }

        return self.readFromWriteBio();
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

        // Set security options
        _ = c.SSL_CTX_set_options(ctx, c.SSL_OP_NO_SSLv2 | c.SSL_OP_NO_SSLv3 | c.SSL_OP_NO_COMPRESSION);

        return ctx;
    }

    fn createSslConnection(ctx: *c.SSL_CTX) !*c.SSL {
        const ssl = c.SSL_new(ctx) orelse {
            return TlsError.TlsConnectionFailed;
        };
        return ssl;
    }

    fn performHandshake(self: *TlsServer) !void {
        const handshake_result = c.SSL_do_handshake(self.ssl);

        if (handshake_result == 1) {
            self.handshake_complete = true;
            return;
        }

        const ssl_error = c.SSL_get_error(self.ssl, handshake_result);
        if (ssl_error == c.SSL_ERROR_WANT_READ or ssl_error == c.SSL_ERROR_WANT_WRITE) {
            return; // Need more data
        }

        std.log.err("TLS handshake failed with error: {}", .{ssl_error});
        self.logOpenSslError();
        return TlsError.TlsHandshakeFailed;
    }

    fn readDecryptedData(self: *TlsServer) !?[]const u8 {
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

    fn handleSslReadError(self: *TlsServer, bytes_read: c_int) !?[]const u8 {
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

    fn logOpenSslError(self: *TlsServer) void {
        _ = self;
        const err_code = c.ERR_get_error();
        if (err_code == 0) return;

        var err_buf: [256]u8 = undefined;
        _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
        std.log.err("OpenSSL error: {s}", .{std.mem.sliceTo(&err_buf, 0)});
    }

    fn writeEncryptedData(self: *TlsServer, data: []const u8) !void {
        if (!self.handshake_complete) {
            std.log.warn("Attempt to encrypt data before handshake complete", .{});
            return TlsError.TlsNotReady;
        }

        const bytes_written = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (bytes_written > 0) return;

        const ssl_error = c.SSL_get_error(self.ssl, bytes_written);
        if (ssl_error == c.SSL_ERROR_WANT_READ or ssl_error == c.SSL_ERROR_WANT_WRITE) {
            return;
        }

        std.log.err("SSL_write failed with error: {}", .{ssl_error});
        self.logOpenSslError();
        return TlsError.TlsWriteFailed;
    }

    fn readFromWriteBio(self: *TlsServer) !?[]const u8 {
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
};
