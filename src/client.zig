const std = @import("std");
const xev = @import("xev");
const pcol = @import("protocol.zig");
const fp = @import("frame_pool.zig");
const base64 = std.base64;
const random = std.crypto.random;
const Loop = xev.Loop;
const TCP = xev.TCP;
const Completion = xev.Completion;
const CallbackAction = xev.CallbackAction;
const ShutdownError = xev.ShutdownError;
const CloseError = xev.CloseError;
const ConnectError = xev.ConnectError;
const WriteError = xev.WriteError;
const ReadError = xev.ReadError;
const WriteBuffer = xev.WriteBuffer;
const ReadBuffer = xev.ReadBuffer;
const ConnectionState = pcol.ConnectionState;
const FramePool = fp.FramePool;
const WebSocketOpCode = pcol.WebSocketOpCode;

pub const Error = error{
    UpgradeFailed,
    ReadError,
    WriteError,
    CloseError,
    ShutdownError,
    FramePayloadTooLarge,
    BufferTooSmall,
    EOF,
    ThreadPoolRequired,
    CanNotHandleFragmentedMessages,
    AlreadyConnected,
};

pub const Client = struct {
    loop: *Loop,
    socket: TCP,
    allocator: std.mem.Allocator,
    connection_state: ConnectionState = .initial,
    read_buf: [1024]u8,
    server_addr: std.net.Address,
    connect_completion: Completion = .{},
    write_completion: Completion = .{},
    read_completion: Completion = .{},
    ping_completion: Completion = .{},
    pending_writes: [128]xev.Async,
    pending_writes_index: usize = 0,
    pending_writes_payloads: [128]pendingWritesQueuePayload = undefined,
    current_write_frame: ?[]u8 = null,
    frame_pool: FramePool,

    callback_context: *anyopaque,
    read_callback: *const fn (
        context: *anyopaque,
        payload: []const u8,
    ) void,

    receive_buffer: std.ArrayList(u8),
    fragment_buffer: std.ArrayList(u8),

    pub fn init(
        allocator: std.mem.Allocator,
        loop: *Loop,
        server_addr: std.net.Address,
        comptime read_callback: *const fn (
            context: *anyopaque,
            payload: []const u8,
        ) void,
        context: *anyopaque,
    ) !Client {
        const frame_pool = try FramePool.init(allocator, 5, 256);
        const receive_buffer = std.ArrayList(u8).init(allocator);
        const fragment_buffer = std.ArrayList(u8).init(allocator);
        return .{
            .allocator = allocator,
            .loop = loop,
            .read_buf = undefined,
            .frame_pool = frame_pool,
            .read_callback = read_callback,
            .server_addr = server_addr,
            .receive_buffer = receive_buffer,
            .fragment_buffer = fragment_buffer,
            .socket = try TCP.init(server_addr),
            .pending_writes = try makePendingWrites(),
            .context = context,
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.connection_state == .connected) {
            self.sendCloseFrame(1000) catch |err| {
                std.debug.print("Failed to send close frame during deinit: {s}\n", .{@errorName(err)});
            };
        }
        if (self.current_write_frame != null) {
            self.frame_pool.release(self.current_write_frame.?);
            self.current_write_frame = null;
        }
        self.frame_pool.deinit();
        self.receive_buffer.deinit();
        self.fragment_buffer.deinit();
    }

    fn makePendingWrites() ![128]xev.Async {
        var arr: [128]xev.Async = undefined;
        for (0..arr.len) |i| {
            arr[i] = try xev.Async.init();
        }
        return arr;
    }

    pub fn start(self: *Client) !void {
        self.socket.connect(self.loop, &self.connect_completion, self.server_addr, Client, self, connectCallback);
    }

    fn connectCallback(
        self_: ?*Client,
        l: *Loop,
        c: *Completion,
        socket: TCP,
        r: ConnectError!void,
    ) CallbackAction {
        r catch |err| {
            std.debug.print("Callback error: {s}\n", .{@errorName(err)});
            return .disarm;
        };

        const self = self_.?;
        var key_buf: [base64.standard.Encoder.calcSize(16)]u8 = undefined;
        const upgrade_request = generateWsUpgradeRequest(self.allocator, "ws.kraken.com", "/v2", &key_buf) catch |err| {
            std.debug.print("Failed to generate upgrade request: {s}\n", .{@errorName(err)});
            return .disarm;
        };
        socket.write(l, c, .{ .slice = upgrade_request }, Client, self, upgradeWriteCallback);
        return .disarm;
    }
    fn upgradeWriteCallback(
        self_: ?*Client,
        l: *Loop,
        c: *Completion,
        socket: TCP,
        _: WriteBuffer,
        r: WriteError!usize,
    ) CallbackAction {
        _ = r catch |err| {
            std.debug.print("Callback error: {s}\n", .{@errorName(err)});
            return .disarm;
        };

        const self = self_.?;
        self.connection_state = .handshake_sent;
        socket.read(l, c, .{ .slice = &self.read_buf }, Client, self, upgradeReadCallback);
        return .disarm;
    }
    fn upgradeReadCallback(
        self_: ?*Client,
        l: *Loop,
        c: *Completion,
        socket: TCP,
        buf: ReadBuffer,
        r: ReadError!usize,
    ) CallbackAction {
        const self = self_.?;
        const bytes_read = r catch |err| {
            std.debug.print("Upgrade Read error: {s}\n", .{@errorName(err)});
            socket.close(l, c, Client, self, closeCallback);
            return .disarm;
        };

        const response_data = buf.slice[0..bytes_read];
        const header_end_marker = "\r\n\r\n";
        const header_end_index = std.mem.indexOf(u8, response_data, header_end_marker);

        if (header_end_index == null) {
            std.debug.print("Incomplete HTTP response received.\n", .{});
            socket.close(l, c, Client, self, closeCallback);
            return .disarm;
        }

        const header_part = response_data[0..header_end_index.?];
        const body_part_start_index = header_end_index.? + header_end_marker.len;

        if (std.mem.indexOf(u8, header_part, "101 Switching Protocols") != null) {
            std.debug.print("WebSocket connection established.\n", .{});
            self.connection_state = .connected;

            // TODO Restructure this to something better
            for (self.pending_writes[0..self.pending_writes_index]) |pw| {
                pw.notify() catch |err| {
                    std.debug.print("Failed to notify pending write: {s}\n", .{@errorName(err)});
                };
            }
            self.startPingTimer() catch |err| {
                std.debug.print("Failed to start ping timer: {s}\n", .{@errorName(err)});
            };

            if (body_part_start_index < response_data.len) {
                const initial_ws_data = response_data[body_part_start_index..];
                self.receive_buffer.appendSlice(initial_ws_data) catch |err| {
                    std.debug.print("Failed to append initial WS data: {s}\n", .{@errorName(err)});
                    socket.close(l, c, Client, self, closeCallback);
                    return .disarm;
                };

                self.processBufferedWebSocketData(l, c, socket) catch |err| {
                    std.debug.print("Error processing initial WS data: {s}\n", .{@errorName(err)});
                    socket.close(l, c, Client, self, closeCallback);
                    return .disarm;
                };
            }

            socket.read(l, &self.read_completion, .{ .slice = &self.read_buf }, Client, self, readCallback);
        } else {
            std.debug.print("WebSocket upgrade failed. Server response:\n{s}\n", .{header_part});
            socket.close(l, c, Client, self, closeCallback);
        }
        return .disarm;
    }

    pub fn write(self: *Client, msg: []const u8) !void {
        if (self.connection_state != .connected) {
            return self.queueWrite(msg);
        }
        const frame = try self.createTextFrame(msg);
        if (self.current_write_frame != null) {
            self.frame_pool.release(self.current_write_frame.?);
        }
        self.current_write_frame = frame;
        self.socket.write(self.loop, &self.write_completion, .{ .slice = frame }, Client, self, writeCallback);
    }
    fn writeCallback(
        self_: ?*Client,
        _: *Loop,
        _: *Completion,
        _: TCP,
        _: WriteBuffer,
        r: WriteError!usize,
    ) CallbackAction {
        _ = r catch |err| {
            std.debug.print("Callback error: {s}\n", .{@errorName(err)});
            return .disarm;
        };
        const self = self_.?;
        if (self.current_write_frame != null) {
            self.frame_pool.release(self.current_write_frame.?);
            self.current_write_frame = null;
        }
        return .disarm;
    }

    const pendingWritesQueuePayload = struct {
        client: *Client,
        msg: []const u8,
    };
    pub fn queueWrite(self: *Client, msg: []const u8) !void {
        if (self.connection_state == .connected) {
            return Error.AlreadyConnected;
        }
        const asnc = self.pending_writes[self.pending_writes_index];
        self.pending_writes_payloads[self.pending_writes_index] = pendingWritesQueuePayload{
            .client = self,
            .msg = try self.allocator.dupe(u8, msg),
        };
        asnc.wait(
            self.loop,
            &self.write_completion,
            pendingWritesQueuePayload,
            &self.pending_writes_payloads[self.pending_writes_index],
            queueWriteCallback,
        );
        self.pending_writes_index += 1;
    }
    fn queueWriteCallback(
        self_: ?*pendingWritesQueuePayload,
        _: *Loop,
        _: *Completion,
        _: xev.Async.WaitError!void,
    ) CallbackAction {
        const payload = self_.?;
        payload.client.write(payload.msg) catch |err| {
            std.debug.print("Failed to write to socket: {s}\n", .{@errorName(err)});
        };
        return .disarm;
    }

    pub fn read(
        self: *Client,
    ) !void {
        self.socket.read(
            self.loop,
            &self.read_completion,
            .{ .slice = &self.read_buf },
            Client,
            self,
            readCallback,
        );
    }
    fn readCallback(
        self_: ?*Client,
        l: *Loop,
        c: *Completion,
        socket: TCP,
        buf: ReadBuffer,
        r: ReadError!usize,
    ) CallbackAction {
        const self = self_.?;
        const n = r catch |err| {
            if (err == Error.EOF) {
                std.debug.print("Connection closed by server (EOF)\n", .{});
            } else {
                std.debug.print("Read error: {s}\n", .{@errorName(err)});
            }
            self.connection_state = .closing;
            return .disarm;
        };

        if (n == 0) {
            socket.read(l, c, .{ .slice = &self.read_buf }, Client, self, readCallback);
            return .disarm;
        }

        const received_data = buf.slice[0..n];
        self.receive_buffer.appendSlice(received_data) catch |err| {
            std.debug.print("Failed to append to receive buffer: {s}\n", .{@errorName(err)});
            socket.close(l, c, Client, self, closeCallback);
            return .disarm;
        };

        self.processBufferedWebSocketData(l, c, socket) catch |err| {
            std.debug.print("Error processing buffered WS data: {s}\n", .{@errorName(err)});
            socket.close(l, c, Client, self, closeCallback);
            return .disarm;
        };

        if (self.connection_state != .closing) {
            socket.read(l, c, .{ .slice = &self.read_buf }, Client, self, readCallback);
        }
        return .disarm;
    }

    fn processBufferedWebSocketData(
        self: *Client,
        l: *Loop,
        c: *Completion,
        socket: TCP,
    ) !void {
        var buffer_view = self.receive_buffer.items;
        var offset: usize = 0;
        while (true) {
            const remaining_data = buffer_view[offset..];
            if (remaining_data.len < 2) break;

            const first_byte = remaining_data[0];
            const second_byte = remaining_data[1];
            const fin = (first_byte & 0x80) != 0;
            const opcode_u8 = first_byte & 0x0F;
            const masked = (second_byte & 0x80) != 0;

            if (masked) {
                std.debug.print("Protocol Error: Received masked frame from server.\n", .{});
                self.sendCloseFrame(1002) catch |err| {
                    std.debug.print("Error sending close frame for protocol error: {s}\n", .{@errorName(err)});
                };
                self.connection_state = .closing;
                socket.shutdown(l, c, Client, self, shutdownCallback);
                return;
            }

            const payload_len_initial = second_byte & 0x7F;
            var header_size: usize = 2;
            var payload_len: usize = 0;

            if (payload_len_initial == 126) {
                header_size = 4;
                if (remaining_data.len < header_size) break;
                payload_len = (@as(usize, remaining_data[2]) << 8) | remaining_data[3];
            } else if (payload_len_initial == 127) {
                header_size = 10;
                if (remaining_data.len < header_size) break;
                const high_bytes = std.mem.readInt(u64, remaining_data[2..10], .big);
                if (high_bytes > std.math.maxInt(usize)) {
                    std.debug.print("Error: Frame payload exceeds usize limit!\n", .{});
                    self.sendCloseFrame(1009) catch |err| {
                        std.debug.print("Error sending close frame for oversized payload: {s}\n", .{@errorName(err)});
                    };
                    self.connection_state = .closing;
                    socket.shutdown(l, c, Client, self, shutdownCallback);
                    return;
                }
                payload_len = @intCast(high_bytes);
            } else {
                payload_len = payload_len_initial;
            }

            if (remaining_data.len < header_size) break;

            const total_frame_size = header_size + payload_len;
            if (remaining_data.len < total_frame_size) break;

            const frame_data = remaining_data[0..total_frame_size];
            const payload_data = frame_data[header_size..];
            try self.handleWebSocketFrame(l, c, socket, @intCast(opcode_u8), fin, payload_data);

            offset += total_frame_size;
            if (self.connection_state == .closing) break;
        }

        if (offset > 0) {
            try self.receive_buffer.replaceRange(0, offset, &[_]u8{});
        }
    }

    fn handleWebSocketFrame(
        self: *Client,
        l: *Loop,
        c: *Completion,
        socket: TCP,
        opcode_u8: u4,
        fin: bool,
        payload: []const u8,
    ) !void {
        // Try to safely convert to WebSocketOpCode enum first
        const opcode = std.meta.intToEnum(WebSocketOpCode, opcode_u8) catch {
            // Handle invalid/reserved opcodes
            std.debug.print("Protocol Error: Unknown or reserved frame type received: {d}\n", .{opcode_u8});
            try self.sendCloseFrame(1002); // Protocol error
            self.connection_state = .closing;
            socket.shutdown(l, c, Client, self, shutdownCallback);
            return;
        };

        // Now we can switch on the enum directly
        switch (opcode) {
            // Data frames
            .text, .binary => {
                try self.handleDataFrame(l, c, socket, opcode, fin, payload);
            },

            // Control frames
            .close, .ping, .pong => {
                try self.handleControlFrame(l, c, socket, opcode, fin, payload);
            },

            // Can't handle other frames yet
            else => {
                std.debug.print("Protocol Error: Unexpected frame\n", .{});
                try self.sendCloseFrame(1002); // Protocol error
                self.connection_state = .closing;
                socket.shutdown(l, c, Client, self, shutdownCallback);
                return;
            },
        }
    }

    fn handleDataFrame(
        self: *Client,
        _: *Loop,
        _: *Completion,
        _: TCP,
        _: WebSocketOpCode,
        fin: bool,
        payload: []const u8,
    ) !void {
        if (!fin) {
            return Error.CanNotHandleFragmentedMessages;
        }
        self.read_callback(self.callback_context, payload);
    }

    fn handleControlFrame(
        self: *Client,
        l: *Loop,
        c: *Completion,
        socket: TCP,
        op: WebSocketOpCode,
        fin: bool,
        payload: []const u8,
    ) !void {
        if (!fin) {
            std.debug.print("Protocol Error: Received fragmented control frame (opcode: {d}).\n", .{@intFromEnum(op)});
            try self.sendCloseFrame(1002); // Protocol error
            self.connection_state = .closing;
            socket.shutdown(l, c, Client, self, shutdownCallback);
            return;
        }
        if (payload.len > 125) {
            std.debug.print("Protocol Error: Received control frame with payload > 125 bytes (opcode: {d}).\n", .{@intFromEnum(op)});
            try self.sendCloseFrame(1002); // Protocol error
            self.connection_state = .closing;
            socket.shutdown(l, c, Client, self, shutdownCallback);
            return;
        }

        switch (op) {
            .close => {
                var close_code: u16 = 1005; // No Status Rcvd
                var reason_slice: []const u8 = "";
                if (payload.len >= 2) {
                    close_code = std.mem.readInt(u16, payload[0..2], .big);
                    if (payload.len > 2) {
                        reason_slice = payload[2..];
                        // Ensure reason is valid UTF-8
                        if (!std.unicode.utf8ValidateSlice(reason_slice)) {
                            std.debug.print("Close received: code={d}, reason (invalid UTF-8): {any}\n", .{ close_code, reason_slice });
                            close_code = 1007; // Invalid frame payload data
                        } else {
                            std.debug.print("Close received: code={d}, reason='{s}'\n", .{ close_code, reason_slice });
                        }
                    } else {
                        std.debug.print("Close received: code={d}\n", .{close_code});
                    }
                } else if (payload.len == 1) {
                    std.debug.print("Close received: code=1002 (payload length 1)\n", .{});
                    close_code = 1002; // Protocol error
                } else {
                    std.debug.print("Close received: code=1005 (no code/payload in frame)\n", .{});
                }

                // Validate close codes
                switch (close_code) {
                    // Reserved codes that MUST NOT be sent in Close frames
                    1005, 1006, 1015 => {
                        std.debug.print("Protocol Error: Received reserved close code {d}.\n", .{close_code});
                        close_code = 1002;
                    },
                    // Codes outside valid application/library ranges (0-999 are reserved for protocol)
                    0...999 => {
                        std.debug.print("Protocol Error: Received reserved close code {d}.\n", .{close_code});
                        close_code = 1002;
                    },
                    // Codes outside defined ranges (non-standard codes sent by server)
                    1016...2999, 5000...std.math.maxInt(u16) => {
                        std.debug.print("Protocol Error: Received unassigned or out-of-range close code {d}.\n", .{close_code});
                        close_code = 1002;
                    },
                    // Valid codes (1000-1014, 3000-4999) are implicitly handled by the lack of a case
                    else => {}, // Assume other codes (1000-1014, 3000-4999) are valid unless specified otherwise
                }

                if (self.connection_state != .closing) {
                    self.connection_state = .closing;
                    // Respond with Close frame (use 1000 for normal closure, or echo error code if appropriate)
                    // Sending 1002 if we received an invalid code/payload.
                    const response_code: u16 = if (close_code == 1002 or close_code == 1007) 1002 else 1000;
                    self.sendCloseFrame(response_code) catch |err| {
                        // Best effort: Log error, but proceed with shutdown
                        std.debug.print("Error sending close frame response: {s}\n", .{@errorName(err)});
                    };
                    // Start the closing handshake
                    socket.shutdown(l, c, Client, self, shutdownCallback);
                }
                // If already closing, we just received the ack, don't send another close.
                return; // Don't process further after close
            },
            .ping => {
                std.debug.print("Ping received with payload: {s}\n", .{payload});
                try self.sendPongFrame(payload);
            },
            .pong => {
                std.debug.print("Pong received with payload: {s}\n", .{payload});
                // Pong is often used as a heartbeat confirmation, no action needed here usually
            },
            else => unreachable, // Should only be close, ping, pong within this branch
        }
    }

    fn shutdownCallback(
        self_: ?*Client,
        l: *Loop,
        c: *Completion,
        socket: TCP,
        r: ShutdownError!void,
    ) CallbackAction {
        r catch |err| {
            std.debug.print("Callback error: {s}\n", .{@errorName(err)});
            return .disarm;
        };

        const self = self_.?;
        socket.close(l, c, Client, self, closeCallback);
        return .disarm;
    }
    fn closeCallback(
        _: ?*Client,
        _: *Loop,
        _: *Completion,
        _: TCP,
        r: CloseError!void,
    ) CallbackAction {
        r catch |err| {
            if (err != Error.ThreadPoolRequired) {
                std.debug.print("Close error: {s}\n", .{@errorName(err)});
            }
        };
        return .disarm;
    }

    fn createTextFrame(self: *Client, text: []const u8) ![]u8 {
        var frame_len = 2 + 4 + text.len;
        if (text.len > 125) {
            if (text.len > 65535) {
                frame_len += 8;
            } else {
                frame_len += 2;
            }
        }
        var frame = try self.frame_pool.acquire(frame_len);
        frame[0] = 0x81;
        var index: usize = 1;
        if (text.len <= 125) {
            frame[index] = @as(u8, @intCast(text.len)) | 0x80;
            index += 1;
        } else if (text.len <= 65535) {
            frame[index] = 126 | 0x80;
            frame[index + 1] = @as(u8, @intCast((text.len >> 8) & 0xFF));
            frame[index + 2] = @as(u8, @intCast(text.len & 0xFF));
            index += 3;
        } else {
            unreachable;
        }
        var mask: [4]u8 = undefined;
        random.bytes(&mask);
        @memcpy(frame[index .. index + 4], &mask);
        index += 4;
        for (text, 0..) |byte, i| {
            frame[index + i] = byte ^ mask[i % 4];
        }
        return frame;
    }

    fn sendCloseFrame(self: *Client, code: u16) !void {
        const frame = try self.createCloseFrame(code);
        if (self.current_write_frame != null) {
            self.frame_pool.release(self.current_write_frame.?);
        }
        self.current_write_frame = frame;
        self.socket.write(self.loop, &self.write_completion, .{ .slice = frame }, Client, self, writeCallback);
        self.connection_state = .closing;
    }

    fn createCloseFrame(self: *Client, code: u16) ![]u8 {
        var frame = try self.frame_pool.acquire(8);
        frame[0] = 0x88;
        frame[1] = 0x82;
        var mask: [4]u8 = undefined;
        random.bytes(&mask);
        @memcpy(frame[2..6], &mask);
        frame[6] = @as(u8, @intCast((code >> 8) & 0xFF)) ^ mask[0];
        frame[7] = @as(u8, @intCast(code & 0xFF)) ^ mask[1];
        return frame;
    }

    fn startPingTimer(self: *Client) !void {
        self.loop.timer(&self.ping_completion, 1000 * 10, self, pingTimerCallback);
    }

    fn pingTimerCallback(
        ud: ?*anyopaque,
        _: *xev.Loop,
        _: *xev.Completion,
        _: xev.Result,
    ) CallbackAction {
        const self = @as(*Client, @ptrCast(@alignCast(ud.?)));

        if (self.connection_state == .connected) {
            self.sendPingFrame() catch |err| {
                std.debug.print("Failed to send ping: {s}\n", .{@errorName(err)});
            };
            self.startPingTimer() catch |err| {
                std.debug.print("Failed to start ping timer: {s}\n", .{@errorName(err)});
            };
        }
        return .disarm;
    }

    fn sendPingFrame(self: *Client) !void {
        const frame = try self.createControlFrame(.ping, "ping");
        if (self.current_write_frame != null) {
            self.frame_pool.release(self.current_write_frame.?);
        }
        self.current_write_frame = frame;
        self.socket.write(self.loop, &self.write_completion, .{ .slice = frame }, Client, self, writeCallback);
    }

    fn createControlFrame(self: *Client, op_code: WebSocketOpCode, payload: []const u8) ![]u8 {
        const frame_len = 2 + 4 + payload.len;
        var frame = try self.frame_pool.acquire(frame_len);
        frame[0] = 0x80 | @as(u8, @intFromEnum(op_code));
        frame[1] = @as(u8, @intCast(payload.len)) | 0x80;
        var mask: [4]u8 = undefined;
        random.bytes(&mask);
        @memcpy(frame[2..6], &mask);
        for (payload, 0..) |byte, i| {
            frame[6 + i] = byte ^ mask[i % 4];
        }
        return frame;
    }

    fn sendPongFrame(self: *Client, payload: []const u8) !void {
        var pong_payload: []const u8 = payload;
        if (pong_payload.len > 125) {
            pong_payload = pong_payload[0..125];
        }
        const frame = try self.createControlFrame(.pong, pong_payload);
        if (self.current_write_frame != null) {
            self.frame_pool.release(self.current_write_frame.?);
        }
        self.current_write_frame = frame;
        self.socket.write(self.loop, &self.write_completion, .{ .slice = frame }, Client, self, writeCallback);
    }

    fn generateWsUpgradeRequest(allocator: std.mem.Allocator, host: []const u8, path: []const u8, key_buf: []u8) ![]u8 {
        var key_bytes: [16]u8 = undefined;
        random.bytes(&key_bytes);
        const encoded_key = base64.standard.Encoder.encode(key_buf, &key_bytes);
        return std.fmt.allocPrint(allocator, "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Accept: */*\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "User-Agent: ZigWebSocketClient/0.1\r\n" ++
            "\r\n", .{ path, host, encoded_key });
    }
};
