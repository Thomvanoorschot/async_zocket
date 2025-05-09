const std = @import("std");
const wss = @import("wss.zig");

const random = std.crypto.random;
const WebSocketOpCode = wss.WebSocketOpCode;

pub fn createTextFrame(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var frame_len = 2 + 4 + text.len;
    if (text.len > 125) {
        if (text.len > 65535) {
            frame_len += 8;
        } else {
            frame_len += 2;
        }
    }
    var frame = try allocator.alloc(u8, frame_len);
    frame[0] = 0x81;
    var index: usize = 1;
    if (text.len <= 125) {
        frame[index] = @as(u8, @intCast(text.len)) | 0x80;
        index += 1;
    } else if (text.len <= 65535) {
        frame[index] = 126 | 0x80;
        frame[index + 1] = @as(u8, @intCast((text.len >> 8) & 0xFF));
        frame[index + 2] = @as(u8, @intCast(text.len & 0xFF));
        index += 3;
    } else {
        unreachable;
    }
    var mask: [4]u8 = undefined;
    random.bytes(&mask);
    @memcpy(frame[index .. index + 4], &mask);
    index += 4;
    for (text, 0..) |byte, i| {
        frame[index + i] = byte ^ mask[i % 4];
    }
    return frame;
}

pub fn createControlFrame(allocator: std.mem.Allocator, op_code: WebSocketOpCode, payload: []const u8) ![]u8 {
    const frame_len = 2 + 4 + payload.len;
    var frame = try allocator.alloc(u8, frame_len);
    frame[0] = 0x80 | @as(u8, @intFromEnum(op_code));
    frame[1] = @as(u8, @intCast(payload.len)) | 0x80;
    var mask: [4]u8 = undefined;
    random.bytes(&mask);
    @memcpy(frame[2..6], &mask);
    for (payload, 0..) |byte, i| {
        frame[6 + i] = byte ^ mask[i % 4];
    }
    return frame;
}
