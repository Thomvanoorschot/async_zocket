const std = @import("std");
const xev = @import("xev");
const client_tcp = @import("client_tcp.zig");
const wss = @import("client_wss.zig");
const core_types = @import("core_types.zig");
const boring_tls = @import("boring_tls");
const tls_clnt = boring_tls.tls_client;

const QueuedWrite = core_types.QueuedWrite;
const ConnectionState = core_types.ConnectionState;

const ClientConfig = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
    use_tls: bool = false,
    verify_certificate: bool = true,
};

// TODO This is a bit of a hack
var cancel_completion: xev.Completion = undefined;
pub const Client = struct {
    loop: *xev.Loop,
    socket: xev.TCP,
    allocator: std.mem.Allocator,
    config: ClientConfig,
    address: std.net.Address,

    connect_completion: xev.Completion = undefined,
    read_completion: xev.Completion = undefined,
    close_completion: xev.Completion = undefined,
    ping_completion: xev.Completion = undefined,

    connection_state: ConnectionState = .disconnected,
    read_buf: [1024]u8 = undefined,

    write_queue: xev.WriteQueue,
    queued_write_pool: std.heap.MemoryPool(QueuedWrite),

    callback_context: *anyopaque,
    read_callback: *const fn (
        context: *anyopaque,
        payload: []const u8,
    ) anyerror!void,

    pending_websocket_writes: std.ArrayList([]const u8),
    incomplete_frame_buffer: []u8 = &[_]u8{},
    incomplete_http_response_buffer: []u8 = &[_]u8{},

    tls_client: ?tls_clnt.TlsClient = null,

    const Self = @This();
    pub fn init(
        allocator: std.mem.Allocator,
        loop: *xev.Loop,
        config: ClientConfig,
        comptime read_callback: *const fn (
            context: *anyopaque,
            payload: []const u8,
        ) anyerror!void,
        callback_context: *anyopaque,
    ) !Self {
        const address = std.net.Address.parseIp4(config.host, config.port) catch blk: {
            const addr_list = try std.net.getAddressList(allocator, config.host, config.port);
            defer addr_list.deinit();

            if (addr_list.addrs.len == 0) {
                return error.HostnameResolutionFailed;
            }

            break :blk addr_list.addrs[0];
        };

        const self = Self{
            .allocator = allocator,
            .loop = loop,
            .address = address,
            .socket = try xev.TCP.init(address),
            .config = config,

            .read_callback = read_callback,
            .callback_context = callback_context,

            .write_queue = xev.WriteQueue{},
            .queued_write_pool = std.heap.MemoryPool(QueuedWrite).init(allocator),

            .pending_websocket_writes = std.ArrayList([]const u8).init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.connection_state = .closing;
        self.cancelCompletion(&self.ping_completion);
        client_tcp.closeSocket(self);
    }
    pub fn deinitMemory(self: *Self) void {
        for (self.pending_websocket_writes.items) |item| {
            self.allocator.free(item);
        }
        self.pending_websocket_writes.deinit();

        if (self.incomplete_frame_buffer.len > 0) {
            self.allocator.free(self.incomplete_frame_buffer);
        }

        if (self.incomplete_http_response_buffer.len > 0) {
            self.allocator.free(self.incomplete_http_response_buffer);
        }

        self.queued_write_pool.deinit();

        if (self.tls_client != null) {
            self.tls_client.?.deinit();
        }
    }

    pub fn connect(self: *Self) void {
        client_tcp.connect(
            self,
            self.loop,
            &self.connect_completion,
            self.address,
        );
    }

    pub fn read(client: *Client) void {
        wss.read(client);
    }

    pub fn write(client: *Client, data: []const u8) !void {
        try wss.write(client, data, .text);
    }

    fn cancelCompletion(client: *Client, completion: *xev.Completion) void {
        if (completion.op != .timer) {
            return;
        }
        cancel_completion = .{
            .op = .{
                .cancel = .{
                    .c = completion,
                },
            },
            .callback = (struct {
                fn callback(
                    _: ?*anyopaque,
                    _: *xev.Loop,
                    _: *xev.Completion,
                    r: xev.Result,
                ) xev.CallbackAction {
                    _ = r.cancel catch unreachable;
                    return .disarm;
                }
            }).callback,
        };
        client.loop.add(&cancel_completion);
    }
};

test "create client" {
    std.testing.log_level = .info;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const wrapperStruct = struct {
        const Self = @This();
        received_response: bool = false,
        fn read_callback(context: *anyopaque, payload: []const u8) !void {
            const self = @as(*Self, @ptrCast(@alignCast(context)));
            std.log.info("read_callback: {s}\n", .{payload});
            self.received_response = true;
        }
    };
    var ws = wrapperStruct{};

    var client = try Client.init(
        std.testing.allocator,
        &loop,
        .{
            .host = "echo.websocket.events",
            .port = 80,
            .path = "/",
            .use_tls = false,
        },
        wrapperStruct.read_callback,
        @ptrCast(&ws),
    );
    client.connect();

    const start_time = std.time.milliTimestamp();
    const duration_ms = 1000;

    while (std.time.milliTimestamp() - start_time < duration_ms) {
        try loop.run(.no_wait);
    }
    client.deinit();
    try loop.run(.once);

    std.testing.expect(ws.received_response) catch {
        std.log.err("Test failed: No echo response received within timeout", .{});
    };
}

test "create TLS client" {
    std.testing.log_level = .info;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const wrapperStruct = struct {
        const Self = @This();
        received_response: bool = false,
        fn read_callback(context: *anyopaque, payload: []const u8) !void {
            const self = @as(*Self, @ptrCast(@alignCast(context)));
            std.log.info("read_callback: {s}\n", .{payload});
            self.received_response = true;
        }
    };
    var ws = wrapperStruct{};

    var client = try Client.init(
        std.testing.allocator,
        &loop,
        .{
            .host = "echo.websocket.org",
            .port = 443,
            .path = "/",
            .use_tls = true,
        },
        wrapperStruct.read_callback,
        @ptrCast(&ws),
    );
    client.connect();

    const start_time = std.time.milliTimestamp();
    const duration_ms = 3000;

    while (std.time.milliTimestamp() - start_time < duration_ms) {
        try loop.run(.once);

        if (client.connection_state == .ready) {
            try client.write("Hello, WSS!");
            break;
        }
    }

    const response_start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() - response_start < 2000) {
        try loop.run(.no_wait);
    }

    client.deinit();
    while (std.time.milliTimestamp() - response_start < 4000) {
        try loop.run(.no_wait);
    }

    std.testing.expect(ws.received_response) catch {
        std.log.err("Test failed: No echo response received within timeout", .{});
    };
}
