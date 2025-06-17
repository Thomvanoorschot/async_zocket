const std = @import("std");
const xev = @import("xev");
const clnt_conn = @import("client_connection.zig");

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
        // self.listen_socket.close();
        // self.accept_completion.cancel(self.loop);

        while (self.connections.pop()) |client_conn| {
            client_conn.close();
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

        // Don't start TLS handshake here - let it happen when data arrives
        // if (self.options.use_tls) {
        //     client_conn.startTlsHandshake() catch |err| {
        //         std.log.err("Failed to start TLS handshake: {any}", .{err});
        //         client_conn.close();
        //         return .rearm;
        //     };
        // }

        return self.on_accept_cb(
            self.cb_ctx,
            self.loop,
            &self.accept_completion,
            client_conn,
        );
    }

    pub fn returnConnection(self: *Self, client_conn: *ClientConnection) void {
        defer self.allocator.destroy(client_conn);
        std.log.info("Returning connection fd={d}", .{client_conn.socket.fd});

        for (self.connections.items, 0..) |conn, i| {
            if (conn == client_conn) {
                _ = self.connections.swapRemove(i);
                break;
            }
        }
    }
};

// test "create server" {
//     std.testing.log_level = .info;
//     var loop = try xev.Loop.init(.{});
//     defer loop.deinit();

//     const wrapperStruct = struct {
//         const Self = @This();
//         fn accept_callback(
//             _: ?*anyopaque,
//             _: *xev.Loop,
//             _: *xev.Completion,
//             cc: *ClientConnection,
//         ) xev.CallbackAction {
//             cc.setReadCallback(
//                 @ptrCast(cc),
//                 read_callback,
//             );
//             cc.read();
//             return .rearm;
//         }
//         fn read_callback(
//             context: ?*anyopaque,
//             payload: []const u8,
//         ) !void {
//             _ = context;
//             std.log.info("read_callback: {s}", .{payload});
//         }
//     };
//     var ws = wrapperStruct{};

//     var server = try Server.init(
//         std.testing.allocator,
//         &loop,
//         .{
//             .host = "127.0.0.1",
//             .port = 8081,
//             .max_connections = 10,
//         },
//         @ptrCast(&ws),
//         wrapperStruct.accept_callback,
//     );
//     server.accept();

//     // Accept
//     try loop.run(.once);
//     // Read
//     try loop.run(.once);
//     // Write
//     try loop.run(.once);
//     // Read
//     try loop.run(.once);

//     server.deinit();
// }

test "create TLS server" {
    std.testing.log_level = .info;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const TestState = struct {
        const Self = @This();
        received_message: bool = false,
        server_ptr: ?*Server = null,

        fn accept_callback(
            ctx: ?*anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            cc: *ClientConnection,
        ) xev.CallbackAction {
            std.log.info("Client connected", .{});
            cc.setReadCallback(ctx.?, read_callback);
            cc.read();
            return .rearm;
        }

        fn read_callback(
            context: ?*anyopaque,
            payload: []const u8,
        ) !void {
            const self = @as(*Self, @ptrCast(@alignCast(context.?)));
            std.log.info("Received WebSocket message: {s}", .{payload});
            self.received_message = true;
        }
    };

    var test_state = TestState{};

    var server = try Server.init(
        std.testing.allocator,
        &loop,
        .{
            .host = "127.0.0.1",
            .port = 8081,
            .max_connections = 10,
            .use_tls = true,
            .cert_file = "server.crt",
            .key_file = "server.key",
        },
        @ptrCast(&test_state),
        TestState.accept_callback,
    );
    defer server.deinit();

    test_state.server_ptr = &server;
    server.accept();

    const start_time = std.time.milliTimestamp();
    const max_duration_ms = 10000;

    while (std.time.milliTimestamp() - start_time < max_duration_ms) {
        try loop.run(.once);

        if (test_state.received_message) {
            std.log.info("Test completed successfully - received WebSocket message", .{});
            break;
        }
    }

    std.testing.expect(test_state.received_message) catch {
        std.log.err("Test completed without receiving WebSocket message", .{});
        std.log.err("Try: websocat -k wss://127.0.0.1:8081", .{});
        std.log.err("And send a message like 'hello'", .{});
    };
}
