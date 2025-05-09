const std = @import("std");
const xev = @import("xev");
const tcp = @import("tcp.zig");
const wss = @import("wss.zig");
const core_types = @import("core_types.zig");

const QueuedWrite = core_types.QueuedWrite;
const ConnectionState = core_types.ConnectionState;

const ClientConfig = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

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

    connection_state: ConnectionState = .initial,
    read_buf: [1024]u8 = undefined,
    delayed_writes: [1028][]u8 = undefined,
    delayed_writes_completions: [1028]xev.Completion = undefined,
    delayed_writes_index: usize = 0,
    write_queue: xev.WriteQueue,
    queued_write_pool: std.heap.MemoryPool(QueuedWrite),

    callback_context: *anyopaque,
    read_callback: *const fn (
        context: *anyopaque,
        payload: []const u8,
    ) anyerror!void,

    receive_buffer: std.ArrayList(u8),
    fragment_buffer: std.ArrayList(u8),

    pub fn init(
        allocator: std.mem.Allocator,
        loop: *xev.Loop,
        config: ClientConfig,
        comptime read_callback: *const fn (
            context: *anyopaque,
            payload: []const u8,
        ) anyerror!void,
        callback_context: *anyopaque,
    ) !Client {
        const receive_buffer = std.ArrayList(u8).init(allocator);
        const fragment_buffer = std.ArrayList(u8).init(allocator);
        const address = try std.net.Address.parseIp4(config.host, config.port);
        return .{
            .allocator = allocator,
            .loop = loop,
            .address = address,
            .socket = try xev.TCP.init(address),
            .config = config,
            .receive_buffer = receive_buffer,
            .fragment_buffer = fragment_buffer,

            .read_callback = read_callback,
            .callback_context = callback_context,

            .write_queue = xev.WriteQueue{},
            .queued_write_pool = std.heap.MemoryPool(QueuedWrite).init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.connection_state == .connected) {
            self.sendCloseFrame(1000) catch |err| {
                std.debug.print("Failed to send close frame during deinit: {s}\n", .{@errorName(err)});
            };
        }
        self.frame_pool.deinit();
        self.receive_buffer.deinit();
        self.fragment_buffer.deinit();
        self.queued_write_pool.deinit();
    }

    pub fn connect(self: *Client) !void {
        tcp.connect(
            self,
            self.loop,
            &self.connect_completion,
            self.address,
        );
    }

    pub fn read(self: *Client) !void {
        wss.read(self);
    }

    pub fn write(self: *Client, data: []const u8) !void {
        try wss.write(self, data);
    }
};
