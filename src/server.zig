const std = @import("std");
const xev = @import("xev");
const clnt_conn = @import("server_client_connection.zig");
const Client = @import("client.zig").Client;

const Allocator = std.mem.Allocator;
const Loop = xev.Loop;
const TCP = xev.TCP;
const Completion = xev.Completion;
const ClientConnection = clnt_conn.ClientConnection;

pub const ServerOptions = struct {
    host: []const u8,
    port: u16,
    max_connections: u31 = 1024,
    use_tls: bool = false,
    cert_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
};

pub const Server = struct {
    allocator: Allocator,
    loop: *Loop,
    options: ServerOptions,
    listen_socket: TCP,
    accept_completion: Completion = undefined,
    connections: std.ArrayList(*ClientConnection),
    is_shutting_down: bool = false,

    cb_ctx: *anyopaque,
    on_accept_cb: *const fn (
        self_: ?*anyopaque,
        _: *xev.Loop,
        _: *xev.Completion,
        client_conn: *ClientConnection,
    ) xev.CallbackAction,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        loop: *Loop,
        options: ServerOptions,
        cb_ctx: *anyopaque,
        on_accept_cb: *const fn (
            self_: ?*anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            client_conn: *ClientConnection,
        ) xev.CallbackAction,
    ) !Self {
        const address = try std.net.Address.parseIp4(options.host, options.port);
        var self = Self{
            .allocator = allocator,
            .loop = loop,
            .options = options,
            .listen_socket = try TCP.init(address),
            .connections = std.ArrayList(*ClientConnection).init(allocator),
            .cb_ctx = cb_ctx,
            .on_accept_cb = on_accept_cb,
        };
        errdefer self.deinit();

        try self.listen_socket.bind(address);
        try self.listen_socket.listen(options.max_connections);

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.is_shutting_down = true;

        // Clean up connections without calling close() to avoid circular cleanup
        for (self.connections.items) |client_conn| {
            client_conn.is_closing = true;
            client_conn.deinit();
            self.allocator.destroy(client_conn);
        }
        self.connections.deinit();
    }

    pub fn accept(self: *Self) void {
        self.listen_socket.accept(
            self.loop,
            &self.accept_completion,
            Self,
            self,
            acceptCallback,
        );
    }

    fn acceptCallback(
        self_: ?*Self,
        _: *Loop,
        _: *Completion,
        result: xev.AcceptError!TCP,
    ) xev.CallbackAction {
        const self = self_ orelse unreachable;
        const client_socket = result catch |err| {
            std.log.err("Failed to accept connection: {s}", .{@errorName(err)});
            return .rearm;
        };

        const client_conn = ClientConnection.init(
            self.allocator,
            self,
            client_socket,
        ) catch |err| {
            std.log.err("Failed to allocate memory for client connection: {s}", .{@errorName(err)});
            // client_socket.close();
            return .rearm;
        };

        self.connections.append(client_conn) catch unreachable;

        if (self.connections.items.len >= self.options.max_connections) {
            std.log.warn("Max connections ({d}) reached, rejecting new connection from fd {d}", .{ self.options.max_connections, client_socket.fd });
            client_conn.close();
            return .rearm;
        }

        std.log.info("Accepted connection {}/{}", .{ self.connections.items.len, self.options.max_connections });

        return self.on_accept_cb(
            self.cb_ctx,
            self.loop,
            &self.accept_completion,
            client_conn,
        );
    }

    pub fn returnConnection(self: *Self, client_conn: *ClientConnection) void {
        if (self.is_shutting_down) return;
        for (self.connections.items, 0..) |conn, i| {
            if (conn == client_conn) {
                _ = self.connections.swapRemove(i);
                break;
            }
        }
        std.log.info("Returning connection {d}/{d}", .{ self.connections.items.len, self.options.max_connections });
        self.allocator.destroy(client_conn);
    }
};

test "create server" {
    std.testing.log_level = .info;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const TestState = struct {
        const Self = @This();
        server_received_message: bool = false,
        client_received_message: bool = false,
        server_ptr: ?*Server = null,
        client_ptr: ?*Client = null,

        fn server_accept_callback(
            ctx_: ?*anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            cc: *ClientConnection,
        ) xev.CallbackAction {
            const ctx = @as(*Self, @ptrCast(@alignCast(ctx_.?)));
            cc.setReadCallback(ctx, server_read_callback);
            cc.read();
            return .rearm;
        }

        fn server_read_callback(
            context: ?*anyopaque,
            payload: []const u8,
        ) !void {
            const self = @as(*Self, @ptrCast(@alignCast(context.?)));
            std.log.info("Server received: {s}", .{payload});
            self.server_received_message = true;
        }

        fn client_read_callback(
            context: *anyopaque,
            payload: []const u8,
        ) !void {
            const self = @as(*Self, @ptrCast(@alignCast(context)));
            std.log.info("Client received: {s}", .{payload});
            self.client_received_message = true;
        }
    };

    var test_state = TestState{};

    var server = try Server.init(
        std.testing.allocator,
        &loop,
        .{
            .host = "127.0.0.1",
            .port = 8082,
            .max_connections = 10,
        },
        @ptrCast(&test_state),
        TestState.server_accept_callback,
    );
    defer server.deinit();

    test_state.server_ptr = &server;
    server.accept();

    var client = try Client.init(
        std.testing.allocator,
        &loop,
        .{
            .host = "127.0.0.1",
            .port = 8082,
            .path = "/",
            .use_tls = false,
        },
        TestState.client_read_callback,
        @ptrCast(&test_state),
    );
    defer {
        client.deinit();
        client.deinitMemory();
    }

    test_state.client_ptr = &client;
    client.connect();

    const start_time = std.time.milliTimestamp();
    const max_duration_ms = 5000;
    var message_sent = false;

    while (std.time.milliTimestamp() - start_time < max_duration_ms) {
        try loop.run(.no_wait);

        // Send message once client is connected
        if (!message_sent and client.connection_state == .ready) {
            try client.write("Hello from test client!");
            message_sent = true;
            std.log.info("Test message sent to server", .{});
        }

        // Break if we received the message
        if (test_state.server_received_message) {
            std.log.info("Test completed successfully - server received message", .{});
            break;
        }
    }

    // Give some time for cleanup
    const cleanup_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - cleanup_start < 1000) {
        try loop.run(.no_wait);
    }

    try std.testing.expect(test_state.server_received_message);
}

test "create TLS server" {
    std.testing.log_level = .info;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const TestState = struct {
        const Self = @This();
        server_received_message: bool = false,
        client_received_message: bool = false,
        server_ptr: ?*Server = null,
        client_ptr: ?*Client = null,

        fn server_accept_callback(
            _: ?*anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            _: *ClientConnection,
        ) xev.CallbackAction {
            return .rearm;
        }

        fn server_read_callback(
            context: ?*anyopaque,
            payload: []const u8,
        ) !void {
            const self = @as(*Self, @ptrCast(@alignCast(context.?)));
            std.log.info("TLS Server received: {s}", .{payload});
            self.server_received_message = true;
        }

        fn client_read_callback(
            context: *anyopaque,
            payload: []const u8,
        ) !void {
            const self = @as(*Self, @ptrCast(@alignCast(context)));
            std.log.info("TLS Client received: {s}", .{payload});
            self.client_received_message = true;
        }
    };

    var test_state = TestState{};

    var server = try Server.init(
        std.testing.allocator,
        &loop,
        .{
            .host = "127.0.0.1",
            .port = 8084,
            .max_connections = 10,
            .use_tls = true,
            .cert_file = "server.crt",
            .key_file = "server.key",
        },
        @ptrCast(&test_state),
        TestState.server_accept_callback,
    );
    defer server.deinit();

    test_state.server_ptr = &server;
    server.accept();

    var client = try Client.init(
        std.testing.allocator,
        &loop,
        .{
            .host = "127.0.0.1",
            .port = 8084,
            .path = "/",
            .use_tls = true,
            .verify_peer = false,
        },
        TestState.client_read_callback,
        @ptrCast(&test_state),
    );
    defer {
        client.deinit();
        client.deinitMemory();
    }

    test_state.client_ptr = &client;
    client.connect();

    const start_time = std.time.milliTimestamp();
    const max_duration_ms = 5000;
    var message_sent = false;

    while (std.time.milliTimestamp() - start_time < max_duration_ms) {
        try loop.run(.no_wait);

        // Send message once client is connected
        if (!message_sent and client.connection_state == .ready) {
            try client.write("Hello from TLS test client!");
            message_sent = true;
            std.log.info("TLS test message sent to server", .{});
        }

        if (test_state.server_received_message) {
            std.log.info("TLS test completed successfully - server received message", .{});
            break;
        }
    }

    const cleanup_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - cleanup_start < 1000) {
        try loop.run(.no_wait);
    }

    try std.testing.expect(test_state.server_received_message);
}
