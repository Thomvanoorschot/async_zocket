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
const DelayedWrite = core_types.DelayedWrite;

const closeSocket = tcp.closeSocket;
const createTextFrame = wss_frame.createTextFrame;
const createCloseFrame = wss_frame.createCloseFrame;
const createControlFrame = wss_frame.createControlFrame;

pub const WebSocketOpCode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    ping = 0x9,
    pong = 0xA,
    close = 0x8,
};

pub fn handleConnectionEstablished(
    client: *Client,
    response_data: []const u8,
    body_part_start_index: usize,
) !void {
    std.log.info("WebSocket connection established.\n", .{});
    client.connection_state = .websocket_connection_established;
    try startPingTimer(client);

    if (body_part_start_index < response_data.len) {
        const initial_ws_data = response_data[body_part_start_index..];
        try client.receive_buffer.appendSlice(initial_ws_data);

        try processBufferedWebSocketData(
            client,
            client.loop,
            &client.connect_completion,
            client.socket,
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
        if (err == Error.EOF) {
            std.log.info("Connection closed by server (EOF)\n", .{});
        } else {
            std.log.err("Read error: {s}\n", .{@errorName(err)});
        }
        closeSocket(client);
        return .disarm;
    };

    if (n == 0) {
        read(client);
        return .disarm;
    }

    const received_data = buf.slice[0..n];
    client.receive_buffer.appendSlice(received_data) catch |err| {
        std.log.err("Failed to append to receive buffer: {s}\n", .{@errorName(err)});
        closeSocket(client);
        return .disarm;
    };

    processBufferedWebSocketData(client, l, c, socket) catch |err| {
        std.log.err("Error processing buffered WS data: {s}\n", .{@errorName(err)});
        closeSocket(client);
        return .disarm;
    };

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
        return try delayWrite(client, payload);
    }
    
    const frame = switch (op) {
        .text => try createTextFrame(client.allocator, payload),
        .ping, .pong => try createControlFrame(client.allocator, op, payload),
        else => return Error.InvalidOpCode,
    };
    const queued_payload: *QueuedWrite = try client.queued_write_pool.create();
    queued_payload.* = .{
        .client = client,
        .frame = frame,
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

fn delayWrite(client: *Client, payload: []const u8) !void {
    const delayFn = struct {
        fn inner(
            ud: ?*anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.Result,
        ) xev.CallbackAction {
            const dw: *DelayedWrite = @as(*DelayedWrite, @ptrCast(@alignCast(ud.?)));
            const c = dw.client;
            write(c, dw.payload, .text) catch unreachable;

            return .disarm;
        }
    }.inner;

    if (client.delayed_write_index >= 1028) {
        return Error.DelayedWritesBufferFull;
    }
    for (0..client.delayed_write_index) |i| {
        if (std.mem.eql(u8, client.delayed_writes[i].payload, payload)) {
            client.loop.timer(
                &client.delayed_writes[i].completion,
                1000,
                @ptrCast(client.delayed_writes[i]),
                delayFn,
            );
            return;
        }
    }

    // TODO: This is still a memory leak. Need to shuffle things around
    const delayed_write = try client.allocator.create(DelayedWrite);
    delayed_write.* = .{
        .client = client,
        .payload = try client.allocator.dupe(u8, payload),
    };
    client.delayed_writes[client.delayed_write_index] = delayed_write;
    client.delayed_write_index += 1;

    client.loop.timer(
        &delayed_write.completion,
        1000,
        @ptrCast(delayed_write),
        delayFn,
    );
}

fn onWrite(
    write_payload: ?*QueuedWrite,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    _: xev.WriteBuffer,
    r: xev.WriteError!usize,
) CallbackAction {
    _ = r catch |err| {
        std.log.err("Callback error: {s}\n", .{@errorName(err)});
        return .disarm;
    };
    const self = write_payload.?.client;
    self.queued_write_pool.destroy(write_payload.?);
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
        "User-Agent: ZigWebSocketClient/0.1\r\n" ++
        "\r\n", .{ path, host, encoded_key });
}

fn processBufferedWebSocketData(
    client: *Client,
    l: *xev.Loop,
    c: *xev.Completion,
    socket: xev.TCP,
) !void {
    var buffer_view = client.receive_buffer.items;
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
            return Error.ReceivedMaskedFrame;
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
                return Error.ReceivedOversizedFrame;
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
        try handleWebSocketFrame(client, l, c, socket, @intCast(opcode_u8), fin, payload_data);

        offset += total_frame_size;
        if (client.connection_state == .closing) break;
    }

    if (offset > 0) {
        try client.receive_buffer.replaceRange(0, offset, &[_]u8{});
    }
}

fn handleWebSocketFrame(
    client: *Client,
    l: *xev.Loop,
    c: *xev.Completion,
    socket: xev.TCP,
    opcode_u8: u4,
    fin: bool,
    payload: []const u8,
) !void {
    const opcode = std.meta.intToEnum(WebSocketOpCode, opcode_u8) catch {
        return Error.ReceivedInvalidOpcode;
    };
    switch (opcode) {
        .text, .binary => {
            try handleDataFrame(
                client,
                l,
                c,
                socket,
                opcode,
                fin,
                payload,
            );
        },
        .close, .ping, .pong => {
            try handleControlFrame(
                client,
                l,
                c,
                socket,
                opcode,
                fin,
                payload,
            );
        },
        else => return Error.ReceivedUnexpectedFrame,
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
    if (!fin) {
        return Error.CanNotHandleFragmentedMessages;
    }
    try client.read_callback(client.callback_context, payload);
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
    const frame = try createControlFrame(
        client.allocator,
        .ping,
        "ping",
    );
    try write(client, frame, .ping);
}

fn sendPongFrame(client: *Client, payload: []const u8) !void {
    var pong_payload: []const u8 = payload;
    if (pong_payload.len > 125) {
        pong_payload = pong_payload[0..125];
    }
    const frame = try createControlFrame(
        client.allocator,
        .pong,
        pong_payload,
    );
    try write(client, frame, .pong);
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
