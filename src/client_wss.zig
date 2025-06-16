const std = @import("std");
const base64 = @import("std").base64;
const xev = @import("xev");
const clnt = @import("client.zig");
const tcp = @import("tcp.zig");
const wss_frame = @import("wss_frame.zig");
const core_types = @import("core_types.zig");

const Client = clnt.Client;
const Error = core_types.Error;
const CallbackAction = xev.CallbackAction;
const random = std.crypto.random;
const QueuedWrite = core_types.QueuedWrite;
const WebSocketOpCode = core_types.WebSocketOpCode;

const closeSocket = tcp.closeSocket;
const createTextFrame = wss_frame.createTextFrame;
const createCloseFrame = wss_frame.createCloseFrame;
const createControlFrame = wss_frame.createControlFrame;

pub fn handleConnectionEstablished(
    client: *Client,
    response_data: []const u8,
    body_part_start_index: usize,
) !void {
    client.connection_state = .websocket_connection_established;
    if (client.tls_client != null) {
        std.log.info("TLS websocket connection established.\n", .{});
    } else {
        std.log.info("Websocket connection established.\n", .{});
    }
    for (client.pending_websocket_writes.items) |payload| {
        try write(client, payload, .text);
    }
    try startPingTimer(client);

    if (body_part_start_index < response_data.len) {
        const initial_ws_data = response_data[body_part_start_index..];
        try handleWebSocketBuffer(
            client,
            client.loop,
            &client.connect_completion,
            client.socket,
            initial_ws_data,
        );
    }

    read(client);
}

pub fn read(
    client: *Client,
) void {
    client.socket.read(
        client.loop,
        &client.read_completion,
        .{ .slice = &client.read_buf },
        Client,
        client,
        onRead,
    );
}

fn onRead(
    client_: ?*Client,
    l: *xev.Loop,
    c: *xev.Completion,
    socket: xev.TCP,
    buf: xev.ReadBuffer,
    r: xev.ReadError!usize,
) CallbackAction {
    const client = client_.?;
    const n = r catch |err| {
        if (err == Error.EOF) {} else {
            std.log.err("Read error: {s}\n", .{@errorName(err)});
        }
        closeSocket(client);
        return .disarm;
    };

    if (n == 0) {
        read(client);
        return .disarm;
    }

    const raw_data = buf.slice[0..n];

    const websocket_data = if (client.tls_client) |tls_client| blk: {
        const decrypted = tls_client.processIncoming(raw_data) catch |err| {
            std.log.err("TLS decrypt error: {s}\n", .{@errorName(err)});
            closeSocket(client);
            return .disarm;
        };

        const outgoing = tls_client.processOutgoing(null) catch |err| {
            std.log.err("TLS outgoing error: {s}\n", .{@errorName(err)});
            closeSocket(client);
            return .disarm;
        };

        if (outgoing) |data| {
            const queued_payload: *QueuedWrite = client.queued_write_pool.create() catch |err| {
                std.log.err("Failed to create queued payload for TLS: {s}\n", .{@errorName(err)});
                return .disarm;
            };
            queued_payload.* = .{
                .client = client,
                .frame = client.allocator.dupe(u8, data) catch |err| {
                    std.log.err("Failed to duplicate TLS outgoing data: {s}\n", .{@errorName(err)});
                    client.queued_write_pool.destroy(queued_payload);
                    return .disarm;
                },
            };
            socket.queueWrite(
                l,
                &client.write_queue,
                &queued_payload.req,
                .{ .slice = queued_payload.frame },
                QueuedWrite,
                queued_payload,
                onWrite,
            );
        }

        break :blk decrypted;
    } else raw_data;

    if (websocket_data) |data| {
        handleWebSocketBuffer(
            client,
            l,
            c,
            socket,
            data,
        ) catch |err| {
            std.log.err("Error handling WS buffer: {s}\n", .{@errorName(err)});
            closeSocket(client);
            return .disarm;
        };
    }

    if (client.connection_state != .closing) {
        read(client);
    }
    return .disarm;
}

pub fn write(
    client: *Client,
    payload: []const u8,
    op: WebSocketOpCode,
) !void {
    if (client.connection_state != .websocket_connection_established) {
        const copied_payload = try client.allocator.dupe(u8, payload);
        try client.pending_websocket_writes.append(copied_payload);
        return;
    }
    const frame = switch (op) {
        .text => try createTextFrame(client.allocator, payload, op, true),
        .ping, .pong => try createControlFrame(client.allocator, op, payload, true),
        else => return Error.InvalidOpCode,
    };

    const data_to_send = if (client.tls_client) |tls_client| blk: {
        const encrypted = try tls_client.processOutgoing(frame);
        client.allocator.free(frame);
        if (encrypted) |enc_data| {
            break :blk try client.allocator.dupe(u8, enc_data);
        }
        return;
    } else frame;

    const queued_payload: *QueuedWrite = try client.queued_write_pool.create();
    queued_payload.* = .{
        .client = client,
        .frame = data_to_send,
    };
    client.socket.queueWrite(
        client.loop,
        &client.write_queue,
        &queued_payload.req,
        .{ .slice = queued_payload.frame },
        QueuedWrite,
        queued_payload,
        onWrite,
    );
}

fn onWrite(
    write_payload_: ?*QueuedWrite,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    _: xev.WriteBuffer,
    r: xev.WriteError!usize,
) CallbackAction {
    const write_payload = write_payload_ orelse unreachable;
    _ = r catch |err| {
        std.log.err("Callback error: {s}\n", .{@errorName(err)});
        return .disarm;
    };
    const self = write_payload.client;
    self.allocator.free(write_payload.frame);
    self.queued_write_pool.destroy(write_payload);
    return .disarm;
}

pub fn createUpgradeRequest(allocator: std.mem.Allocator, host: []const u8, path: []const u8) ![]u8 {
    var key_buf: [base64.standard.Encoder.calcSize(16)]u8 = undefined;
    var key_bytes: [16]u8 = undefined;
    random.bytes(&key_bytes);
    const encoded_key = base64.standard.Encoder.encode(&key_buf, &key_bytes);
    return std.fmt.allocPrint(allocator, "GET {s} HTTP/1.1\r\n" ++
        "Host: {s}\r\n" ++
        "Accept: */*\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: {s}\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "User-Agent: AsyncZocket/0.1\r\n" ++
        "\r\n", .{ path, host, encoded_key });
}

fn handleWebSocketBuffer(
    client: *Client,
    l: *xev.Loop,
    c: *xev.Completion,
    socket: xev.TCP,
    buffer: []const u8,
) !void {
    var remaining_buffer = buffer;
    if (client.incomplete_frame_buffer.len > 0) {
        remaining_buffer = try std.mem.concat(client.allocator, u8, &.{ client.incomplete_frame_buffer, remaining_buffer });
        client.allocator.free(client.incomplete_frame_buffer);
        client.incomplete_frame_buffer = &[_]u8{};
    }

    while (remaining_buffer.len > 0) {
        const frame = wss_frame.WebSocketFrame.parse(remaining_buffer, client.allocator) catch |err| {
            if (err == error.InsufficientData) {
                client.incomplete_frame_buffer = try client.allocator.dupe(u8, remaining_buffer);
                break;
            }
            std.log.err("Error parsing WS frame: {s}\n", .{@errorName(err)});
            return err;
        };

        switch (frame.opcode) {
            .text, .binary => {
                try handleDataFrame(
                    client,
                    l,
                    c,
                    socket,
                    frame.opcode,
                    frame.fin,
                    frame.payload,
                );
            },
            .close, .ping, .pong => {
                try handleControlFrame(
                    client,
                    l,
                    c,
                    socket,
                    frame.opcode,
                    frame.fin,
                    frame.payload,
                );
            },
            else => return Error.ReceivedUnexpectedFrame,
        }
        var mutable_frame = frame;
        mutable_frame.deinit(client.allocator);
        remaining_buffer = remaining_buffer[frame.total_frame_size..];
    }
}

fn handleDataFrame(
    client: *Client,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    _: WebSocketOpCode,
    fin: bool,
    payload: []const u8,
) !void {
    if (client.connection_state == .websocket_connection_established) {
        if (!fin) {
            return Error.CanNotHandleFragmentedMessages;
        }
        try client.read_callback(client.callback_context, payload);
    }
}

fn handleControlFrame(
    client: *Client,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    op: WebSocketOpCode,
    fin: bool,
    payload: []const u8,
) !void {
    if (!fin) {
        return Error.ReceivedFragmentedControlFrame;
    }
    if (payload.len > 125) {
        return Error.ReceivedOversizedControlFrame;
    }

    switch (op) {
        .close => {
            if (client.connection_state != .closing) {
                closeSocket(client);
            }
            return;
        },
        .ping => try sendPongFrame(client, payload),
        .pong => {},
        else => unreachable,
    }
}

fn sendPingFrame(client: *Client) !void {
    try write(client, "ping", .ping);
}

fn sendPongFrame(client: *Client, payload: []const u8) !void {
    var pong_payload: []const u8 = payload;
    if (pong_payload.len > 125) {
        pong_payload = pong_payload[0..125];
    }
    try write(client, pong_payload, .pong);
}

fn startPingTimer(client: *Client) !void {
    client.loop.timer(
        &client.ping_completion,
        1000 * 10,
        client,
        startPing,
    );
}

fn startPing(
    client_: ?*anyopaque,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.Result,
) CallbackAction {
    const client = @as(*Client, @ptrCast(@alignCast(client_.?)));

    if (client.connection_state == .websocket_connection_established) {
        sendPingFrame(client) catch |err| {
            std.log.err("Failed to send ping: {s}\n", .{@errorName(err)});
        };
        startPingTimer(client) catch |err| {
            std.log.err("Failed to start ping timer: {s}\n", .{@errorName(err)});
        };
    }
    return .disarm;
}
