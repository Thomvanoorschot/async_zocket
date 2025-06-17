const std = @import("std");

pub const c = @cImport({
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
    CertificateVerificationFailed,
    TlsConnectionClosed,
};

pub const BUFFER_SIZE = 4096;

/// Initialize OpenSSL library
pub fn initOpenSsl() void {
    _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);
}

/// Create a new BIO memory buffer
pub fn createBio() !*c.BIO {
    return c.BIO_new(c.BIO_s_mem()) orelse {
        std.log.err("Failed to create BIO", .{});
        return TlsError.BioFailed;
    };
}

/// Create a new SSL instance from an SSL context
pub fn createSslInstance(ctx: *c.SSL_CTX) !*c.SSL {
    return c.SSL_new(ctx) orelse {
        std.log.err("Failed to create SSL instance", .{});
        return TlsError.TlsConnectionFailed;
    };
}

/// Write data to a BIO
pub fn writeToBio(bio: *c.BIO, data: []const u8) !void {
    const written = c.BIO_write(bio, data.ptr, @intCast(data.len));
    if (written <= 0) {
        std.log.err("Failed to write to BIO", .{});
        return TlsError.TlsReadFailed;
    }
}

/// Read data from a BIO into a buffer
pub fn readFromBio(bio: *c.BIO, buffer: []u8) !usize {
    var total_read: usize = 0;
    var temp_buf: [BUFFER_SIZE]u8 = undefined;

    while (total_read < buffer.len) {
        const remaining = buffer.len - total_read;
        const read_size = @min(temp_buf.len, remaining);

        const bytes_read = c.BIO_read(bio, &temp_buf, @intCast(read_size));
        if (bytes_read <= 0) break;

        const actual_read = @as(usize, @intCast(bytes_read));
        @memcpy(buffer[total_read .. total_read + actual_read], temp_buf[0..actual_read]);
        total_read += actual_read;
    }

    return total_read;
}

/// Handle SSL read errors and return appropriate action
pub fn handleSslReadError(ssl: *c.SSL, bytes_read: c_int) !?[]const u8 {
    const ssl_error = c.SSL_get_error(ssl, bytes_read);

    return switch (ssl_error) {
        c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => null,
        c.SSL_ERROR_ZERO_RETURN => TlsError.TlsConnectionClosed,
        else => {
            std.log.err("SSL_read failed with error: {}", .{ssl_error});
            logOpenSslError();
            return TlsError.TlsReadFailed;
        },
    };
}

/// Check if SSL operation needs more data (non-blocking)
pub fn sslWantsMoreData(ssl: *c.SSL, result: c_int) bool {
    const ssl_error = c.SSL_get_error(ssl, result);
    return ssl_error == c.SSL_ERROR_WANT_READ or ssl_error == c.SSL_ERROR_WANT_WRITE;
}

/// Log OpenSSL errors from the error queue
pub fn logOpenSslError() void {
    const err_code = c.ERR_get_error();
    if (err_code == 0) return;

    var err_buf: [256]u8 = undefined;
    _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
    std.log.err("OpenSSL error: {s}", .{std.mem.sliceTo(&err_buf, 0)});
}

/// Log detailed SSL error information including error queue and SSL state
pub fn logDetailedSslError(ssl: *c.SSL) void {
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
    const state = c.SSL_get_state(ssl);
    const state_string = c.SSL_state_string_long(ssl);
    std.log.err("SSL State: {} ({s})", .{ state, @as([*:0]const u8, @ptrCast(state_string)) });

    std.log.err("=== End SSL Error Details ===", .{});
}

/// Common buffer structure for TLS operations
pub const TlsBuffers = struct {
    encrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    encrypted_len: usize = 0,
    decrypted_buffer: [BUFFER_SIZE * 2]u8 = undefined,
    decrypted_len: usize = 0,

    pub fn resetEncrypted(self: *TlsBuffers) void {
        self.encrypted_len = 0;
    }

    pub fn resetDecrypted(self: *TlsBuffers) void {
        self.decrypted_len = 0;
    }

    pub fn getEncryptedSlice(self: *TlsBuffers) []const u8 {
        return self.encrypted_buffer[0..self.encrypted_len];
    }

    pub fn getDecryptedSlice(self: *TlsBuffers) []const u8 {
        return self.decrypted_buffer[0..self.decrypted_len];
    }
};
