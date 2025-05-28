const std = @import("std");
const xev = @import("xev");
const svr = @import("server.zig");
const wss_frame = @import("wss_frame.zig");
const server_wss = @import("server_wss.zig");

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

    cb_ctx: *anyopaque = undefined,
    on_read_cb: *const fn (
        self_: ?*anyopaque,
        payload: []const u8,
    ) void,
    on_close_cb: ?*const fn (
        self_: ?*anyopaque,
    ) anyerror!void = null,

    has_upgraded: bool = false,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        server: *Server,
        socket: TCP,
        cb_ctx: *anyopaque,
        on_read_cb: *const fn (
            self_: ?*anyopaque,
            payload: []const u8,
        ) void,
    ) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .server = server,
            .socket = socket,
            .write_queue = xev.WriteQueue{},
            .queued_write_pool = std.heap.MemoryPool(QueuedWrite).init(allocator),
            .cb_ctx = cb_ctx,
            .on_read_cb = on_read_cb,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.queued_write_pool.deinit();
    }
    pub fn read(
        self: *Self,
    ) void {
        const internal_callback = struct {
            fn inner(
                self_: ?*Self,
                _: *Loop,
                _: *Completion,
                socket: TCP,
                buf: xev.ReadBuffer,
                r: xev.ReadError!usize,
            ) xev.CallbackAction {
                const inner_self = self_ orelse unreachable;
                const bytes_read = r catch |err| {
                    if (err == error.ConnectionResetByPeer) {
                        inner_self.close();
                        return .disarm;
                    }
                    std.log.err("Failed to read: {any}", .{err});
                    inner_self.close();
                    return .disarm;
                };
                if (!inner_self.has_upgraded) {
                    const upgrade_response = server_wss.createUpgradeResponse(
                        inner_self.allocator,
                        buf.slice[0..bytes_read],
                    ) catch |err| {
                        std.log.err("Failed to create upgrade response: {any}", .{err});
                        inner_self.close();
                        return .disarm;
                    };
                    const queued_payload: *QueuedWrite = inner_self.queued_write_pool.create() catch {
                        inner_self.allocator.free(upgrade_response);
                        inner_self.close();
                        return .disarm;
                    };
                    queued_payload.* = .{
                        .client_connection = inner_self,
                        .payload = upgrade_response, 
                    };

                    socket.queueWrite(
                        inner_self.server.loop,
                        &inner_self.write_queue,
                        &queued_payload.req,
                        .{ .slice = queued_payload.payload },
                        QueuedWrite,
                        queued_payload,
                        upgradeWriteCallback,
                    );
                    return .disarm;
                }

                if (bytes_read == 0) {
                    inner_self.close();
                    return .disarm;
                }

                // TODO: Proably make it return something optionally
                inner_self.on_read_cb(inner_self.cb_ctx, buf.slice[0..bytes_read]);
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
        comptime MessageTypes: type,
        message_type: MessageTypes,
        data: std.ArrayList(u8),
    ) !void {
        const queued_payload: *QueuedWrite = try self.queued_write_pool.create();
        queued_payload.* = .{
            .client_connection = self,
            .frame = try Frame.init(
                self.allocator,
                @intFromEnum(message_type),
                data,
            ),
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
    pub fn setCloseCallback(
        self: *Self,
        on_close_ctx: *anyopaque,
        on_close_cb: *const fn (
            self_: ?*anyopaque,
        ) anyerror!void,
    ) void {
        self.cb_ctx = on_close_ctx;
        self.on_close_cb = on_close_cb;
    }
    pub fn close(self: *Self) void {
        self.deinit();
        defer self.server.returnConnection(self);
        if (self.on_close_cb) |cb| {
            cb(self.cb_ctx) catch |close_err| {
                std.log.err("Failed to close connection: {any}", .{close_err});
            };
        }
    }
};
