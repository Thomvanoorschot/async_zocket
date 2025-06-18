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

    // Add a field to handle incomplete frames
    incomplete_frame_buffer: []u8 = &[_]u8{},
    is_closing: bool = false,

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
        if (self.incomplete_frame_buffer.len > 0) {
            self.allocator.free(self.incomplete_frame_buffer);
        }
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
                        inner_self.close();
                        return .disarm;
                    }
                    if (err != error.EOF) {
                        std.log.err("Failed to read: {any}", .{err});
                    }
                    inner_self.close();
                    return .disarm;
                };

                if (bytes_read == 0) {
                    inner_self.close();
                    return .disarm;
                }

                // Handle TLS if enabled
                var processed_data: ?[]const u8 = null;
                if (inner_self.tls_server) |*tls| {
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
                        inner_self.sendTlsData(data) catch |err| {
                            std.log.err("Failed to send TLS response: {}", .{err});
                            inner_self.close();
                            return .disarm;
                        };
                    }

                    inner_self.tls_handshake_complete = tls.isHandshakeComplete();
                    if (decrypted) |data| {
                        processed_data = data;
                    } else {
                        inner_self.read();
                        return .disarm;
                    }
                } else {
                    processed_data = buf.slice[0..bytes_read];
                }

                if (processed_data) |data| {
                    if (!inner_self.has_upgraded) {
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

                    // Handle WebSocket frames - call handleWebSocketData instead of user callback
                    inner_self.handleWebSocketData(data) catch |err| {
                        std.log.err("Failed to process WebSocket data: {any}", .{err});
                        inner_self.close();
                        return .disarm;
                    };
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

            const encrypted_response = tls.processOutgoing(response) catch |err| {
                self.allocator.free(response);
                return err;
            };

            if (encrypted_response) |encrypted| {
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

    fn handleWebSocketData(self: *Self, data: []const u8) !void {
        var remaining_buffer = data;

        if (self.incomplete_frame_buffer.len > 0) {
            remaining_buffer = try std.mem.concat(self.allocator, u8, &.{ self.incomplete_frame_buffer, remaining_buffer });
            self.allocator.free(self.incomplete_frame_buffer);
            self.incomplete_frame_buffer = &[_]u8{};
        }

        while (remaining_buffer.len > 0) {
            const frame = wss_frame.WebSocketFrame.parse(remaining_buffer, self.allocator) catch |err| {
                if (err == error.InsufficientData) {
                    self.incomplete_frame_buffer = try self.allocator.dupe(u8, remaining_buffer);
                    break;
                }
                if (remaining_buffer.len >= 8) {
                    std.log.err("Problematic data length: {}, first 8 bytes: {any}", .{ remaining_buffer.len, remaining_buffer[0..8] });
                } else {
                    std.log.err("Problematic data length: {}, all bytes: {any}", .{ remaining_buffer.len, remaining_buffer });
                }
                return err;
            };

            switch (frame.opcode) {
                .text, .binary => {
                    if (self.on_read_cb) |cb| {
                        try cb(self.read_cb_ctx, frame.payload);
                    }
                },
                .close => {
                    var mutable_frame = frame;
                    mutable_frame.deinit(self.allocator);
                    self.close();
                    return;
                },
                .ping => {
                    try self.write(.pong, frame.payload);
                },
                .pong => {
                    std.log.debug("Received pong frame", .{});
                },
                else => {
                    std.log.warn("Received unsupported frame type: {}", .{frame.opcode});
                },
            }

            var mutable_frame = frame;
            mutable_frame.deinit(self.allocator);
            remaining_buffer = remaining_buffer[frame.total_frame_size..];
        }
    }

    // Modify the upgradeWriteCallback to set up WebSocket frame handling
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

        // Remove the problematic callback setup that was causing recursion
        // The callback should already be set up to receive the final payload

        // Continue reading (the read loop will now handle WebSocket frames properly)
        self.read();
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
        if (self.is_closing) return;
        self.is_closing = true;
        if (self.on_close_cb) |cb| {
            cb(self.close_cb_ctx) catch |close_err| {
                std.log.err("Failed to close connection: {any}", .{close_err});
            };
        }
        self.deinit();

        self.server.returnConnection(self);
    }
};
