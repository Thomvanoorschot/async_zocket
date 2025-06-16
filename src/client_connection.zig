const std = @import("std");
const xev = @import("xev");
const svr = @import("server.zig");
const wss_frame = @import("wss_frame.zig");
const server_wss = @import("server_wss.zig");
const core_types = @import("core_types.zig");
const tls_server = @import("tls_server.zig");

const TCP = xev.TCP;
const Completion = xev.Completion;
const Loop = xev.Loop;
const Server = svr.Server;
const Frame = wss_frame.WebSocketFrame;

const QueuedWrite = struct {
    client_connection: *ClientConnection,
    req: xev.WriteRequest = undefined,
    payload: []u8,
};

pub const ClientConnection = struct {
    allocator: std.mem.Allocator,
    server: *Server,
    socket: TCP,
    read_buffer: [1024]u8 = undefined,
    read_completion: Completion = undefined,
    write_queue: xev.WriteQueue,
    queued_write_pool: std.heap.MemoryPool(QueuedWrite),

    read_cb_ctx: *anyopaque = undefined,
    on_read_cb: ?*const fn (
        self_: ?*anyopaque,
        payload: []const u8,
    ) anyerror!void = null,
    close_cb_ctx: *anyopaque = undefined,
    on_close_cb: ?*const fn (
        self_: ?*anyopaque,
    ) anyerror!void = null,

    has_upgraded: bool = false,
    tls_server: ?tls_server.TlsServer = null,
    tls_handshake_complete: bool = false,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        server: *Server,
        socket: TCP,
    ) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .server = server,
            .socket = socket,
            .write_queue = xev.WriteQueue{},
            .queued_write_pool = std.heap.MemoryPool(QueuedWrite).init(allocator),
        };

        // Initialize TLS if server uses TLS
        if (server.options.use_tls) {
            if (server.options.cert_file == null or server.options.key_file == null) {
                std.log.err("TLS enabled but certificate or key file not provided", .{});
                allocator.destroy(self);
                return error.TlsCertificateRequired;
            }
            self.tls_server = tls_server.TlsServer.init(server.options.cert_file.?, server.options.key_file.?) catch |err| {
                std.log.err("Failed to initialize TLS server: {}", .{err});
                allocator.destroy(self);
                return err;
            };

            // Initialize the connection-specific SSL state
            self.tls_server.?.initConnection() catch |err| {
                std.log.err("Failed to initialize TLS connection: {}", .{err});
                allocator.destroy(self);
                return err;
            };
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.tls_server != null) {
            self.tls_server.?.deinit();
        }
        self.queued_write_pool.deinit();
    }

    pub fn startTlsHandshake(self: *Self) !void {
        if (self.tls_server) |*tls| {
            const handshake_data = tls.startHandshake() catch |err| {
                std.log.err("Failed to start TLS handshake: {any}", .{err});
                return err;
            };

            if (handshake_data) |data| {
                try self.sendTlsData(data);
            }
        }
    }

    pub fn read(
        self: *Self,
    ) void {
        const internal_callback = struct {
            fn inner(
                self_: ?*Self,
                _: *Loop,
                _: *Completion,
                _: TCP,
                buf: xev.ReadBuffer,
                r: xev.ReadError!usize,
            ) xev.CallbackAction {
                const inner_self = self_ orelse unreachable;
                const bytes_read = r catch |err| {
                    if (err == error.ConnectionResetByPeer) {
                        std.log.info("Connection reset by peer", .{});
                        inner_self.close();
                        return .disarm;
                    }
                    std.log.err("Failed to read: {any}", .{err});
                    inner_self.close();
                    return .disarm;
                };

                if (bytes_read == 0) {
                    std.log.info("Connection closed (0 bytes read)", .{});
                    inner_self.close();
                    return .disarm;
                }

                std.log.info("Received {d} bytes, TLS enabled: {}, has_upgraded: {}", .{ bytes_read, inner_self.tls_server != null, inner_self.has_upgraded });

                // Handle TLS if enabled
                var processed_data: ?[]const u8 = null;
                if (inner_self.tls_server) |*tls| {
                    std.log.info("Processing TLS data, handshake complete: {}", .{tls.isHandshakeComplete()});

                    // Process incoming encrypted data
                    const decrypted = tls.processIncoming(buf.slice[0..bytes_read]) catch |err| {
                        std.log.err("TLS processing failed: {}", .{err});
                        // Don't close immediately, log the error and try to continue
                        if (err == tls_server.TlsError.TlsHandshakeFailed or
                            err == tls_server.TlsError.TlsConnectionClosed)
                        {
                            inner_self.close();
                            return .disarm;
                        }
                        // For other errors, try to continue
                        inner_self.read();
                        return .disarm;
                    };

                    // Always check for outgoing data after processing incoming data
                    const encrypted_response = tls.processOutgoing(null) catch |err| {
                        std.log.err("TLS outgoing processing failed: {}", .{err});
                        inner_self.close();
                        return .disarm;
                    };

                    if (encrypted_response) |data| {
                        std.log.info("Sending TLS response: {} bytes (handshake complete: {})", .{ data.len, tls.isHandshakeComplete() });
                        inner_self.sendTlsData(data) catch |err| {
                            std.log.err("Failed to send TLS response: {}", .{err});
                            inner_self.close();
                            return .disarm;
                        };
                    }

                    // Update handshake status after processing
                    const was_handshake_complete = inner_self.tls_handshake_complete;
                    inner_self.tls_handshake_complete = tls.isHandshakeComplete();

                    if (!was_handshake_complete and inner_self.tls_handshake_complete) {
                        std.log.info("TLS handshake just completed!", .{});
                    }

                    if (decrypted) |data| {
                        std.log.info("TLS decrypted {} bytes: {s}", .{ data.len, data });
                        processed_data = data;
                    } else {
                        std.log.info("No decrypted data yet, handshake complete: {}", .{tls.isHandshakeComplete()});
                        // Continue reading for more data
                        inner_self.read();
                        return .disarm;
                    }
                } else {
                    processed_data = buf.slice[0..bytes_read];
                }

                if (processed_data) |data| {
                    if (!inner_self.has_upgraded) {
                        std.log.info("Processing WebSocket upgrade with {d} bytes", .{data.len});
                        const upgrade_response = server_wss.createUpgradeResponse(
                            inner_self.allocator,
                            data,
                        ) catch |err| {
                            std.log.err("Failed to create upgrade response: {any}", .{err});
                            inner_self.close();
                            return .disarm;
                        };

                        inner_self.sendResponse(upgrade_response, upgradeWriteCallback) catch |err| {
                            std.log.err("Failed to send upgrade response: {any}", .{err});
                            inner_self.close();
                            return .disarm;
                        };
                        return .disarm;
                    }

                    // Handle WebSocket frames
                    if (inner_self.on_read_cb) |cb| {
                        cb(inner_self.read_cb_ctx, data) catch |err| {
                            std.log.err("Failed to process WebSocket data: {any}", .{err});
                            inner_self.close();
                            return .disarm;
                        };
                    }
                }

                // Continue reading
                inner_self.read();
                return .disarm;
            }
        }.inner;
        self.socket.read(
            self.server.loop,
            &self.read_completion,
            .{ .slice = &self.read_buffer },
            Self,
            self,
            internal_callback,
        );
    }

    pub fn write(
        self: *Self,
        op: core_types.WebSocketOpCode,
        data: []const u8,
    ) !void {
        const frame_data = try wss_frame.createTextFrame(self.allocator, data, op, false);
        defer self.allocator.free(frame_data);

        if (self.tls_server) |*tls| {
            if (!tls.isHandshakeComplete()) {
                return error.TlsHandshakeNotComplete;
            }

            // Encrypt the frame data
            const encrypted_data = tls.processOutgoing(frame_data) catch |err| {
                std.log.err("TLS encryption failed: {any}", .{err});
                return err;
            };

            if (encrypted_data) |encrypted| {
                try self.sendTlsData(encrypted);
            }
        } else {
            try self.sendPlainData(frame_data);
        }
    }

    fn sendTlsData(self: *Self, data: []const u8) !void {
        const queued_payload: *QueuedWrite = try self.queued_write_pool.create();
        const payload_copy = try self.allocator.dupe(u8, data);

        queued_payload.* = .{
            .client_connection = self,
            .payload = payload_copy,
        };

        self.socket.queueWrite(
            self.server.loop,
            &self.write_queue,
            &queued_payload.req,
            .{ .slice = queued_payload.payload },
            QueuedWrite,
            queued_payload,
            internalWriteCallback,
        );
    }

    fn sendPlainData(self: *Self, data: []const u8) !void {
        const queued_payload: *QueuedWrite = try self.queued_write_pool.create();
        const payload_copy = try self.allocator.dupe(u8, data);

        queued_payload.* = .{
            .client_connection = self,
            .payload = payload_copy,
        };

        self.socket.queueWrite(
            self.server.loop,
            &self.write_queue,
            &queued_payload.req,
            .{ .slice = queued_payload.payload },
            QueuedWrite,
            queued_payload,
            internalWriteCallback,
        );
    }

    fn sendResponse(self: *Self, response: []u8, callback: fn (?*QueuedWrite, *Loop, *Completion, TCP, xev.WriteBuffer, xev.WriteError!usize) xev.CallbackAction) !void {
        var final_response: []u8 = undefined;

        if (self.tls_server) |*tls| {
            if (!tls.isHandshakeComplete()) {
                std.log.err("Attempting to send response before TLS handshake complete", .{});
                self.allocator.free(response);
                return error.TlsHandshakeNotComplete;
            }

            std.log.info("Encrypting response: {d} bytes", .{response.len});
            // Encrypt the response
            const encrypted_response = tls.processOutgoing(response) catch |err| {
                self.allocator.free(response);
                return err;
            };

            if (encrypted_response) |encrypted| {
                std.log.info("Encrypted response: {d} bytes", .{encrypted.len});
                final_response = try self.allocator.dupe(u8, encrypted);
                self.allocator.free(response);
            } else {
                self.allocator.free(response);
                return error.TlsEncryptionFailed;
            }
        } else {
            final_response = response;
        }

        const queued_payload: *QueuedWrite = try self.queued_write_pool.create();
        queued_payload.* = .{
            .client_connection = self,
            .payload = final_response,
        };

        self.socket.queueWrite(
            self.server.loop,
            &self.write_queue,
            &queued_payload.req,
            .{ .slice = queued_payload.payload },
            QueuedWrite,
            queued_payload,
            callback,
        );
    }

    fn internalWriteCallback(
        write_payload_: ?*QueuedWrite,
        _: *Loop,
        _: *Completion,
        _: TCP,
        _: xev.WriteBuffer,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        const write_payload = write_payload_ orelse unreachable;
        const self = write_payload.client_connection;
        defer self.queued_write_pool.destroy(write_payload);
        defer self.allocator.free(write_payload.payload);

        _ = r catch |err| {
            std.log.err("Failed to write: {any}", .{err});
            self.close();
            return .disarm;
        };
        // if (!self.keep_alive) {
        //     self.close();
        // }
        return .disarm;
    }
    fn upgradeWriteCallback(
        write_payload_: ?*QueuedWrite,
        _: *Loop,
        _: *Completion,
        _: TCP,
        _: xev.WriteBuffer,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        const write_payload = write_payload_ orelse unreachable;
        const self = write_payload.client_connection;
        defer self.queued_write_pool.destroy(write_payload);
        defer self.allocator.free(write_payload.payload);

        _ = r catch |err| {
            std.log.err("Failed to write: {any}", .{err});
            self.close();
            return .disarm;
        };
        self.has_upgraded = true;
        // if (!self.keep_alive) {
        //     self.close();
        // }
        server_wss.read(self);
        return .disarm;
    }
    pub fn setReadCallback(
        self: *Self,
        on_read_ctx: *anyopaque,
        on_read_cb: *const fn (
            self_: ?*anyopaque,
            payload: []const u8,
        ) anyerror!void,
    ) void {
        self.read_cb_ctx = on_read_ctx;
        self.on_read_cb = on_read_cb;
    }
    pub fn setCloseCallback(
        self: *Self,
        on_close_ctx: *anyopaque,
        on_close_cb: *const fn (
            self_: ?*anyopaque,
        ) anyerror!void,
    ) void {
        self.close_cb_ctx = on_close_ctx;
        self.on_close_cb = on_close_cb;
    }
    pub fn close(self: *Self) void {
        if (self.on_close_cb) |cb| {
            cb(self.close_cb_ctx) catch |close_err| {
                std.log.err("Failed to close connection: {any}", .{close_err});
            };
        }
        self.deinit();

        self.server.returnConnection(self);
    }
};
