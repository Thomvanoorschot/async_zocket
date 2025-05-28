const std = @import("std");
const base64 = std.base64;

pub fn createUpgradeResponse(allocator: std.mem.Allocator, key: []const u8) ![]u8 {
    const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const accept_raw = std.crypto.hash.sha1.hash(key ++ magic);
    var accept_key_buf: [base64.standard.Encoder.calcSize(accept_raw.len)]u8 = undefined;
    const accept_key = base64.standard.Encoder.encode(&accept_key_buf, &accept_raw);

    return std.fmt.allocPrint(allocator, "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: {s}\r\n" ++
        "\r\n", .{accept_key});
}
