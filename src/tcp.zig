const std = @import("std");
const clnt = @import("client.zig");
const xev = @import("xev");
const wss = @import("wss.zig");
const core_types = @import("core_types.zig");

const Client = clnt.Client;
const Error = core_types.Error;

pub fn connect(
    client: *Client,
    loop: *xev.Loop,
    completion: *xev.Completion,
    server_addr: std.net.Address,
) void {
    client.connection_state = .connecting;
    client.socket.connect(
        loop,
        completion,
        server_addr,
        Client,
        client,
        onConnected,
    );
}

fn onConnected(
    client_: ?*Client,
    l: *xev.Loop,
    c: *xev.Completion,
    socket: xev.TCP,
    r: xev.ConnectError!void,
) xev.CallbackAction {
    const client = client_.?;
    r catch |err| {
        std.log.err("Websocket Connect error: {s}\n", .{@errorName(err)});
        return .disarm;
    };
    const upgrade_request = wss.createUpgradeRequest(
        client.allocator,
        "ws.kraken.com",
        "/v2",
        // client.config.host,
        // client.config.path,
    ) catch |err| {
        std.log.err("Failed to generate upgrade request: {s}\n", .{@errorName(err)});
        return .disarm;
    };
    client.connection_state = .tcp_connected;
    socket.write(
        l,
        c,
        .{ .slice = upgrade_request },
        Client,
        client,
        onWebsocketUpgrade,
    );

    return .disarm;
}

fn onWebsocketUpgrade(
    client_: ?*Client,
    l: *xev.Loop,
    c: *xev.Completion,
    socket: xev.TCP,
    _: xev.WriteBuffer,
    r: xev.WriteError!usize,
) xev.CallbackAction {
    const client = client_.?;
    _ = r catch |err| {
        std.log.err("Websocket Upgrade error: {s}\n", .{@errorName(err)});
        return .disarm;
    };

    client.connection_state = .websocket_handshake_sent;
    socket.read(
        l,
        c,
        .{ .slice = &client.read_buf },
        Client,
        client,
        onWebsocketUpgradeRead,
    );
    return .disarm;
}
fn onWebsocketUpgradeRead(
    client_: ?*Client,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    buf: xev.ReadBuffer,
    r: xev.ReadError!usize,
) xev.CallbackAction {
    const client = client_.?;
    const bytes_read = r catch |err| {
        std.log.err("Upgrade Read error: {s}\n", .{@errorName(err)});
        closeSocket(client);
        return .disarm;
    };

    const response_data = buf.slice[0..bytes_read];
    const header_end_marker = "\r\n\r\n";
    const header_end_index = std.mem.indexOf(u8, response_data, header_end_marker);
    if (header_end_index == null) {
        std.log.err("Incomplete HTTP response received.\n", .{});
        closeSocket(client);
        return .disarm;
    }

    const header_part = response_data[0..header_end_index.?];
    const body_part_start_index = header_end_index.? + header_end_marker.len;

    if (std.mem.indexOf(u8, header_part, "101 Switching Protocols") == null) {
        std.log.err("WebSocket upgrade failed. Server response:\n{s}\n", .{header_part});
        closeSocket(client);
        return .disarm;
    }

    wss.handleConnectionEstablished(
        client,
        response_data,
        body_part_start_index,
    ) catch |err| {
        std.log.err("Error handling connection established: {s}\n", .{@errorName(err)});
        closeSocket(client);
        return .disarm;
    };
    return .disarm;
}

fn shutdownCallback(
    client_: ?*Client,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    r: xev.ShutdownError!void,
) xev.CallbackAction {
    const client = client_.?;
    r catch |err| {
        std.log.err("Shutdown error: {s}\n", .{@errorName(err)});
        return .disarm;
    };

    closeSocket(client);
    return .disarm;
}

pub fn closeSocket(
    client: *Client,
) void {
    client.connection_state = .closing;
    client.socket.close(
        client.loop,
        &client.close_completion,
        Client,
        client,
        closeCallback,
    );
}

fn closeCallback(
    client_: ?*Client,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    r: xev.CloseError!void,
) xev.CallbackAction {
    const client = client_.?;
    r catch |err| {
        if (err != Error.ThreadPoolRequired) {
            std.log.err("Close error: {s}\n", .{@errorName(err)});
        }
    };
    client.connection_state = .closed;
    return .disarm;
}
