const std = @import("std");
const xev = @import("xev");
const tls = @import("tls.zig");

const c = tls.c;
pub const TlsError = tls.TlsError;

const BUFFER_SIZE = tls.BUFFER_SIZE;

pub const TlsClient = struct {
    ssl_ctx: *c.SSL_CTX,
    ssl: *c.SSL,
    bio_read: *c.BIO,
    bio_write: *c.BIO,
    handshake_complete: bool = false,
    hostname: []const u8,

    buffers: tls.TlsBuffers = .{},

    pub fn init(hostname: []const u8) !TlsClient {
        tls.initOpenSsl();

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

        const bio_read = tls.createBio() catch |err| {
            c.SSL_free(ssl);
            c.SSL_CTX_free(ctx);
            return err;
        };

        const bio_write = tls.createBio() catch |err| {
            _ = c.BIO_free(bio_read);
            c.SSL_free(ssl);
            c.SSL_CTX_free(ctx);
            return err;
        };

        c.SSL_set_bio(ssl, bio_read, bio_write);

        return .{
            .ssl_ctx = ctx,
            .ssl = ssl,
            .bio_read = bio_read,
            .bio_write = bio_write,
            .hostname = hostname,
        };
    }

    pub fn deinit(self: *TlsClient) void {
        c.SSL_free(self.ssl);
        c.SSL_CTX_free(self.ssl_ctx);
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

    pub fn processIncoming(self: *TlsClient, encrypted_data: []const u8) !?[]const u8 {
        if (encrypted_data.len == 0) return null;

        try tls.writeToBio(self.bio_read, encrypted_data);

        if (!self.handshake_complete) {
            try self.performHandshake();
        }

        if (!self.handshake_complete) return null;

        return try self.readDecryptedData();
    }

    pub fn processOutgoing(self: *TlsClient, plaintext: ?[]const u8) !?[]const u8 {
        if (plaintext) |data| {
            try self.writeEncryptedData(data);
        }

        return self.readFromWriteBio();
    }

    pub fn isHandshakeComplete(self: *TlsClient) bool {
        return self.handshake_complete;
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
        return tls.createSslInstance(ctx);
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

    fn performHandshake(self: *TlsClient) !void {
        const handshake_result = c.SSL_do_handshake(self.ssl);

        if (handshake_result == 1) {
            self.handshake_complete = true;
            self.verifyCertificate();
            return;
        }

        if (!tls.sslWantsMoreData(self.ssl, handshake_result)) {
            std.log.err("TLS handshake failed with error: {}", .{c.SSL_get_error(self.ssl, handshake_result)});
            return TlsError.TlsHandshakeFailed;
        }
    }

    fn verifyCertificate(self: *TlsClient) void {
        const verify_result = c.SSL_get_verify_result(self.ssl);
        if (verify_result != c.X509_V_OK) {
            std.log.warn("Certificate verification failed: {}", .{verify_result});
        }
    }

    fn readDecryptedData(self: *TlsClient) !?[]const u8 {
        self.buffers.resetDecrypted();
        var temp_buf: [BUFFER_SIZE]u8 = undefined;

        const bytes_read = c.SSL_read(self.ssl, &temp_buf, temp_buf.len);
        if (bytes_read > 0) {
            const read_size = @as(usize, @intCast(bytes_read));
            if (read_size > self.buffers.decrypted_buffer.len) {
                return TlsError.TlsReadFailed;
            }
            @memcpy(self.buffers.decrypted_buffer[0..read_size], temp_buf[0..read_size]);
            self.buffers.decrypted_len = read_size;
            return self.buffers.getDecryptedSlice();
        }

        return try tls.handleSslReadError(self.ssl, bytes_read);
    }

    fn writeEncryptedData(self: *TlsClient, data: []const u8) !void {
        if (!self.handshake_complete) {
            std.log.warn("Attempt to encrypt data before handshake complete", .{});
            return TlsError.TlsNotReady;
        }

        const bytes_written = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (bytes_written > 0) return;

        if (tls.sslWantsMoreData(self.ssl, bytes_written)) return;

        std.log.err("SSL_write failed with error: {}", .{c.SSL_get_error(self.ssl, bytes_written)});
        return TlsError.TlsWriteFailed;
    }

    fn readFromWriteBio(self: *TlsClient) !?[]const u8 {
        self.buffers.resetEncrypted();
        const encrypted_len = try tls.readFromBio(self.bio_write, &self.buffers.encrypted_buffer);
        self.buffers.encrypted_len = encrypted_len;

        return if (self.buffers.encrypted_len > 0) self.buffers.getEncryptedSlice() else null;
    }
};
