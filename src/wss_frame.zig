const std = @import("std");
const core_types = @import("core_types.zig");

const random = std.crypto.random;
const WebSocketOpCode = core_types.WebSocketOpCode;

/// WebSocket frame structure according to RFC 6455
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-------+-+-------------+-------------------------------+
/// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
/// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
/// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
/// | |1|2|3|       |K|             |                               |
/// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
/// |     Extended payload length continued, if payload len == 127  |
/// + - - - - - - - - - - - - - - - +-------------------------------+
/// |                               |Masking-key, if MASK set to 1  |
/// +-------------------------------+-------------------------------+
/// | Masking-key (continued)       |          Payload Data         |
/// +-------------------------------- - - - - - - - - - - - - - - - +
/// :                     Payload Data continued ...                :
/// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
/// |                     Payload Data continued ...                |
/// +---------------------------------------------------------------+
/// ```
pub const WebSocketFrame = struct {
    fin: bool,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: WebSocketOpCode,
    masked: bool = false,
    masking_key: [4]u8 = [4]u8{ 0x12, 0x34, 0x56, 0x78 },
    payload: []const u8,
    total_frame_size: usize = undefined,
    outgoing: bool = false,

    pub fn parse(data: []const u8, allocator: std.mem.Allocator) !WebSocketFrame {
        if (data.len < 2) return error.InsufficientData;

        const first_byte = data[0];
        const second_byte = data[1];

        const fin = (first_byte & 0x80) != 0;
        const rsv1 = (first_byte & 0x40) != 0;
        const rsv2 = (first_byte & 0x20) != 0;
        const rsv3 = (first_byte & 0x10) != 0;
        const opcode_u8 = first_byte & 0x0F;

        const opcode = std.meta.intToEnum(WebSocketOpCode, opcode_u8) catch {
            return error.InvalidOpcode;
        };

        const masked = (second_byte & 0x80) != 0;
        const payload_len_initial = second_byte & 0x7F;

        var header_size: usize = 2;
        var payload_len: usize = 0;

        if (payload_len_initial == 126) {
            if (data.len < 4) return error.InsufficientData;
            header_size = 4;
            payload_len = (@as(usize, data[2]) << 8) | data[3];
        } else if (payload_len_initial == 127) {
            if (data.len < 10) return error.InsufficientData;
            header_size = 10;
            const high_bytes = std.mem.readInt(u64, data[2..10], .big);
            if (high_bytes > std.math.maxInt(usize)) {
                return error.PayloadTooLarge;
            }
            payload_len = @intCast(high_bytes);
        } else {
            payload_len = payload_len_initial;
        }

        var masking_key: [4]u8 = undefined;
        if (masked) {
            if (data.len < header_size + 4) return error.InsufficientData;
            @memcpy(&masking_key, data[header_size .. header_size + 4]);
            header_size += 4;
        }

        const total_frame_size = header_size + payload_len;
        if (data.len < total_frame_size) return error.InsufficientData;

        var payload: []u8 = undefined;
        if (masked) {
            payload = try allocator.alloc(u8, payload_len);
            const masked_payload = data[header_size .. header_size + payload_len];
            for (masked_payload, 0..) |byte, i| {
                payload[i] = byte ^ masking_key[i % 4];
            }
        } else {
            payload = @constCast(data[header_size .. header_size + payload_len]);
        }

        return WebSocketFrame{
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .masked = masked,
            .masking_key = if (masked) masking_key else [4]u8{ 0, 0, 0, 0 },
            .payload = payload,
            .total_frame_size = total_frame_size,
        };
    }

    pub fn getSerializedSize(self: *const WebSocketFrame) usize {
        var size: usize = 2;

        if (self.payload.len > 125) {
            if (self.payload.len > 65535) {
                size += 8;
            } else {
                size += 2;
            }
        }

        if (self.masked) {
            size += 4;
        }
        size += self.payload.len;

        return size;
    }

    pub fn serialize(self: *const WebSocketFrame, allocator: std.mem.Allocator) ![]u8 {
        const total_size = self.getSerializedSize();
        var frame = try allocator.alloc(u8, total_size);
        errdefer allocator.free(frame);

        frame[0] = (@as(u8, if (self.fin) 0x80 else 0)) |
            (@as(u8, if (self.rsv1) 0x40 else 0)) |
            (@as(u8, if (self.rsv2) 0x20 else 0)) |
            (@as(u8, if (self.rsv3) 0x10 else 0)) |
            @as(u8, @intFromEnum(self.opcode));

        var index: usize = 1;

        const mask_bit: u8 = if (self.masked) 0x80 else 0;

        if (self.payload.len <= 125) {
            frame[index] = @as(u8, @intCast(self.payload.len)) | mask_bit;
            index += 1;
        } else if (self.payload.len <= 65535) {
            frame[index] = 126 | mask_bit;
            frame[index + 1] = @as(u8, @intCast((self.payload.len >> 8) & 0xFF));
            frame[index + 2] = @as(u8, @intCast(self.payload.len & 0xFF));
            index += 3;
        } else {
            frame[index] = 127 | mask_bit;
            std.mem.writeInt(u64, frame[index + 1 .. index + 9][0..8], @as(u64, self.payload.len), .big);
            index += 9;
        }

        if (self.masked) {
            @memcpy(frame[index .. index + 4], &self.masking_key);
            index += 4;

            for (self.payload, 0..) |byte, i| {
                frame[index + i] = byte ^ self.masking_key[i % 4];
            }
        } else {
            @memcpy(frame[index .. index + self.payload.len], self.payload);
        }

        return frame;
    }
    pub fn deinit(self: *WebSocketFrame, allocator: std.mem.Allocator) void {
        if (self.outgoing or self.masked) {
            allocator.free(self.payload);
        }
    }
};

pub fn createTextFrame(
    allocator: std.mem.Allocator,
    text: []const u8,
    op: WebSocketOpCode,
    masked: bool,
) ![]u8 {
    const frame = WebSocketFrame{
        .fin = true,
        .opcode = op,
        .masked = masked,
        .payload = text,
        .outgoing = true,
    };
    return frame.serialize(allocator);
}

pub fn createControlFrame(allocator: std.mem.Allocator, op_code: WebSocketOpCode, payload: []const u8, masked: bool) ![]u8 {
    const frame = WebSocketFrame{
        .fin = true,
        .opcode = op_code,
        .masked = masked,
        .payload = payload,
        .outgoing = true,
    };
    return frame.serialize(allocator);
}

pub fn createCloseFrame(allocator: std.mem.Allocator) ![]u8 {
    return createControlFrame(allocator, .close, "");
}
