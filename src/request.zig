const std = @import("std");
const base64 = @import("std").base64;
const random = std.crypto.random;

pub fn generateWsUpgradeRequest(allocator: std.mem.Allocator, host: []const u8, path: []const u8) ![]u8 {
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
