const std = @import("std");
const base64 = std.base64;
const core_types = @import("core_types.zig");
const client_connection = @import("client_connection.zig");
const xev = @import("xev");
const wss_frame = @import("wss_frame.zig");

const HttpRequest = core_types.HttpRequest;
const ClientConnection = client_connection.ClientConnection;
const Loop = xev.Loop;
const Completion = xev.Completion;
const TCP = xev.TCP;

pub fn read(connection: *ClientConnection) void {
    const internal_callback = struct {
        fn inner(
            connection_: ?*ClientConnection,
            _: *Loop,
            _: *Completion,
            _: TCP,
            buf: xev.ReadBuffer,
            r: xev.ReadError!usize,
        ) xev.CallbackAction {
            const inner_connection = connection_ orelse unreachable;
            const bytes_read = r catch |err| {
                if (err == error.ConnectionResetByPeer) {
                    inner_connection.close();
                    return .disarm;
                }
                std.log.err("Failed to read: {any}", .{err});
                inner_connection.close();
                return .disarm;
            };
            var frame = wss_frame.WebSocketFrame.parse(buf.slice[0..bytes_read], inner_connection.allocator) catch |err| {
                std.log.err("Failed to parse frame: {any}", .{err});
                inner_connection.close();
                return .disarm;
            };
            defer frame.deinit(inner_connection.allocator);

            if (bytes_read == 0) {
                inner_connection.close();
                return .disarm;
            }
            if (inner_connection.on_read_cb) |cb| {
                const payload_copy = inner_connection.allocator.dupe(u8, frame.payload) catch {
                    std.log.err("Failed to dupe payload", .{});
                    inner_connection.close();
                    return .disarm;
                };
                cb(inner_connection.read_cb_ctx, payload_copy) catch |err| {
                    std.log.err("Failed to read: {any}", .{err});
                    inner_connection.close();
                    return .disarm;
                };
            }
            return .rearm;
        }
    }.inner;
    connection.socket.read(
        connection.server.loop,
        &connection.read_completion,
        .{ .slice = &connection.read_buffer },
        ClientConnection,
        connection,
        internal_callback,
    );
}

pub fn createUpgradeResponse(allocator: std.mem.Allocator, req_buf: []const u8) ![]u8 {
    var it = std.mem.tokenizeAny(u8, req_buf, "\r\n");
    var request = HttpRequest{};
    while (it.next()) |line| {
        if (std.mem.indexOf(u8, line, ": ")) |colon_pos| {
            const header_name = line[0..colon_pos];
            const header_value = line[colon_pos + 2 ..];

            if (std.mem.eql(u8, header_name, "Host")) {
                request.host = header_value;
            } else if (std.mem.eql(u8, header_name, "Upgrade")) {
                request.upgrade = header_value;
            } else if (std.mem.eql(u8, header_name, "Sec-WebSocket-Version")) {
                request.websocket_version = header_value;
            } else if (std.mem.eql(u8, header_name, "Sec-WebSocket-Key")) {
                request.websocket_key = header_value;
            }
        }
    }
    if (request.websocket_key == null) {
        return error.MissingWebSocketKey;
    }

    var accept_key_buf: [28]u8 = undefined;
    try computeAcceptKey(&accept_key_buf, request.websocket_key.?);

    return std.fmt.allocPrint(allocator, "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: {s}\r\n" ++
        "\r\n", .{accept_key_buf});
}

pub fn computeAcceptKey(accept_key_buf: *[28]u8, requestKey: []const u8) !void {
    const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(requestKey);
    hasher.update(magic);
    var digest: [20]u8 = undefined;
    hasher.final(&digest);

    _ = base64.standard.Encoder.encode(accept_key_buf, &digest);
}
