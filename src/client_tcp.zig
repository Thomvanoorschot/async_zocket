const std = @import("std");
const clnt = @import("client.zig");
const xev = @import("xev");
const wss = @import("client_wss.zig");
const core_types = @import("core_types.zig");
const tls_clnt = @import("tls_client.zig");

const Client = clnt.Client;
const Error = core_types.Error;
const QueuedWrite = core_types.QueuedWrite;

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
        std.log.err("TCP Connect error: {s}\n", .{@errorName(err)});
        return .disarm;
    };

    client.connection_state = .connecting;

    if (client.config.use_tls) {
        client.tls_client = tls_clnt.TlsClient.init(client.config.host, .{
            .verify_peer = client.config.verify_peer,
        }) catch |err| {
            std.log.err("TLS init error: {s}\n", .{@errorName(err)});
            return .disarm;
        };

        const handshake_data = client.tls_client.?.startHandshake() catch |err| {
            std.log.err("TLS handshake start error: {s}\n", .{@errorName(err)});
            return .disarm;
        };

        if (handshake_data) |data| {
            const queued_payload: *QueuedWrite = client.queued_write_pool.create() catch |err| {
                std.log.err("Failed to create queued payload: {s}\n", .{@errorName(err)});
                return .disarm;
            };
            queued_payload.* = .{
                .client = client,
                .frame = client.allocator.dupe(u8, data) catch |err| {
                    std.log.err("Failed to duplicate TLS handshake data: {s}\n", .{@errorName(err)});
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
                onTlsHandshakeWrite,
            );
        } else {
            socket.read(
                l,
                c,
                .{ .slice = &client.read_buf },
                Client,
                client,
                onTlsHandshakeRead,
            );
        }
    } else {
        return startWebSocketUpgrade(client, l, socket);
    }

    return .disarm;
}

fn startWebSocketUpgrade(client: *Client, l: *xev.Loop, socket: xev.TCP) xev.CallbackAction {
    const upgrade_request = wss.createUpgradeRequest(
        client.allocator,
        client.config.host,
        client.config.path,
    ) catch |err| {
        std.log.err("Failed to generate upgrade request: {s}\n", .{@errorName(err)});
        return .disarm;
    };

    const data_to_send = if (client.tls_client != null) blk: {
        const encrypted = client.tls_client.?.processOutgoing(upgrade_request) catch |err| {
            std.log.err("Failed to encrypt upgrade request: {s}\n", .{@errorName(err)});
            client.allocator.free(upgrade_request);
            return .disarm;
        };
        client.allocator.free(upgrade_request);

        if (encrypted) |enc_data| {
            break :blk client.allocator.dupe(u8, enc_data) catch |err| {
                std.log.err("Failed to duplicate encrypted upgrade request: {s}\n", .{@errorName(err)});
                return .disarm;
            };
        } else {
            std.log.err("No encrypted data for upgrade request", .{});
            return .disarm;
        }
    } else upgrade_request;

    const queued_payload: *QueuedWrite = client.queued_write_pool.create() catch |err| {
        std.log.err("Failed to create queued payload: {s}\n", .{@errorName(err)});
        client.allocator.free(data_to_send);
        return .disarm;
    };
    queued_payload.* = .{
        .client = client,
        .frame = data_to_send,
    };
    socket.queueWrite(
        l,
        &client.write_queue,
        &queued_payload.req,
        .{ .slice = queued_payload.frame },
        QueuedWrite,
        queued_payload,
        onWebsocketUpgrade,
    );

    return .disarm;
}

fn onTlsHandshakeWrite(
    write_payload_: ?*QueuedWrite,
    l: *xev.Loop,
    c: *xev.Completion,
    socket: xev.TCP,
    _: xev.WriteBuffer,
    r: xev.WriteError!usize,
) xev.CallbackAction {
    const write_payload = write_payload_.?;
    const client = write_payload.client;
    client.allocator.free(write_payload.frame);
    client.queued_write_pool.destroy(write_payload);

    _ = r catch |err| {
        std.log.err("TLS Handshake write error: {s}\n", .{@errorName(err)});
        return .disarm;
    };

    socket.read(
        l,
        c,
        .{ .slice = &client.read_buf },
        Client,
        client,
        onTlsHandshakeRead,
    );
    return .disarm;
}

fn onTlsHandshakeRead(
    client_: ?*Client,
    l: *xev.Loop,
    c: *xev.Completion,
    socket: xev.TCP,
    buf: xev.ReadBuffer,
    r: xev.ReadError!usize,
) xev.CallbackAction {
    const client = client_.?;
    const bytes_read = r catch |err| {
        std.log.err("TLS Handshake read error: {s}\n", .{@errorName(err)});
        closeSocket(client);
        return .disarm;
    };

    if (bytes_read == 0) {
        std.log.err("TLS Handshake: connection closed by server", .{});
        closeSocket(client);
        return .disarm;
    }

    const received_data = buf.slice[0..bytes_read];

    if (!client.tls_client.?.isHandshakeComplete()) {
        const decrypted_data = client.tls_client.?.processIncoming(received_data) catch |err| {
            std.log.err("TLS handshake process error: {s}\n", .{@errorName(err)});
            closeSocket(client);
            return .disarm;
        };

        if (decrypted_data) |data| {
            const queued_payload: *QueuedWrite = client.queued_write_pool.create() catch |err| {
                std.log.err("Failed to create queued payload: {s}\n", .{@errorName(err)});
                return .disarm;
            };
            queued_payload.* = .{
                .client = client,
                .frame = client.allocator.dupe(u8, data) catch |err| {
                    std.log.err("Failed to duplicate TLS data: {s}\n", .{@errorName(err)});
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
                onTlsHandshakeWrite,
            );
            return .disarm;
        }

        if (client.tls_client.?.isHandshakeComplete()) {
            return startWebSocketUpgrade(client, l, socket);
        } else {
            socket.read(
                l,
                c,
                .{ .slice = &client.read_buf },
                Client,
                client,
                onTlsHandshakeRead,
            );
        }
    }

    return .disarm;
}

fn onWebsocketUpgrade(
    write_payload_: ?*QueuedWrite,
    l: *xev.Loop,
    c: *xev.Completion,
    socket: xev.TCP,
    _: xev.WriteBuffer,
    r: xev.WriteError!usize,
) xev.CallbackAction {
    const write_payload = write_payload_.?;
    const client = write_payload.client;
    client.allocator.free(write_payload.frame);
    client.queued_write_pool.destroy(write_payload);
    _ = r catch |err| {
        std.log.err("Websocket Upgrade error: {s}\n", .{@errorName(err)});
        return .disarm;
    };

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
    l: *xev.Loop,
    c: *xev.Completion,
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

    const raw_response = buf.slice[0..bytes_read];

    const response_data = if (client.tls_client != null) blk: {
        const decrypted = client.tls_client.?.processIncoming(raw_response) catch |err| {
            std.log.err("TLS decrypt error during upgrade: {s}\n", .{@errorName(err)});
            closeSocket(client);
            return .disarm;
        };

        if (decrypted) |data| {
            break :blk data;
        } else {
            client.socket.read(
                l,
                c,
                .{ .slice = &client.read_buf },
                Client,
                client,
                onWebsocketUpgradeRead,
            );
            return .disarm;
        }
    } else raw_response;

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
    client.connection_state = .disconnected;
    defer client.deinitMemory();
    return .disarm;
}
