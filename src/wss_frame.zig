const std = @import("std");
const wss = @import("wss.zig");

const random = std.crypto.random;
const WebSocketOpCode = wss.WebSocketOpCode;

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

    masked: bool,

    masking_key: ?[4]u8 = [4]u8{ 0x12, 0x34, 0x56, 0x78 },

    payload: []const u8,

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !WebSocketFrame {
        std.debug.print("parsing frame: {s}\n", .{data});
        if (data.len < 2) return error.InsufficientData;

        const first_byte = data[0];
        const second_byte = data[1];

        const fin = (first_byte & 0x80) != 0;
        const rsv1 = (first_byte & 0x40) != 0;
        const rsv2 = (first_byte & 0x20) != 0;
        const rsv3 = (first_byte & 0x10) != 0;
        const opcode_u8 = first_byte & 0x0F;

        std.debug.print("opcode_u8: {}\n", .{opcode_u8});
        const opcode = std.meta.intToEnum(WebSocketOpCode, opcode_u8) catch {
            return error.InvalidOpcode;
        };

        // Parse second byte
        const masked = (second_byte & 0x80) != 0;
        const payload_len_initial = second_byte & 0x7F;

        var header_size: usize = 2;
        var payload_len: usize = 0;

        // Determine actual payload length
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

        // Handle masking key
        var masking_key: ?[4]u8 = null;
        if (masked) {
            if (data.len < header_size + 4) return error.InsufficientData;
            masking_key = data[header_size .. header_size + 4][0..4].*;
            header_size += 4;
        }

        // Check if we have enough data for the complete frame
        const total_frame_size = header_size + payload_len;
        if (data.len < total_frame_size) return error.InsufficientData;

        // Extract payload
        var payload = data[header_size .. header_size + payload_len];

        // Unmask payload if needed
        var unmasked_payload: []u8 = undefined;
        if (masked and masking_key != null) {
            unmasked_payload = try allocator.alloc(u8, payload.len);
            for (payload, 0..) |byte, i| {
                unmasked_payload[i] = byte ^ masking_key.?[i % 4];
            }
            payload = unmasked_payload;
        }

        return WebSocketFrame{
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .masked = masked,
            .masking_key = masking_key,
            .payload = payload,
        };
    }

    /// Get the total size this frame would occupy when serialized
    pub fn getSerializedSize(self: *const WebSocketFrame) usize {
        var size: usize = 2; // Basic header

        // Extended payload length
        if (self.payload.len > 125) {
            if (self.payload.len > 65535) {
                size += 8; // 64-bit length
            } else {
                size += 2; // 16-bit length
            }
        }

        // Masking key
        if (self.masked) {
            size += 4;
        }

        // Payload
        size += self.payload.len;

        return size;
    }

    /// Serialize the frame to bytes
    pub fn serialize(self: *const WebSocketFrame, allocator: std.mem.Allocator) ![]u8 {
        const total_size = self.getSerializedSize();
        var frame = try allocator.alloc(u8, total_size);

        // First byte: FIN + RSV + Opcode
        frame[0] = (@as(u8, if (self.fin) 0x80 else 0)) |
            (@as(u8, if (self.rsv1) 0x40 else 0)) |
            (@as(u8, if (self.rsv2) 0x20 else 0)) |
            (@as(u8, if (self.rsv3) 0x10 else 0)) |
            @as(u8, @intFromEnum(self.opcode));

        var index: usize = 1;

        // Second byte: MASK + Payload length
        if (self.payload.len <= 125) {
            frame[index] = @as(u8, @intCast(self.payload.len)) |
                (@as(u8, if (self.masked) 0x80 else 0));
            index += 1;
        } else if (self.payload.len <= 65535) {
            frame[index] = 126 | (@as(u8, if (self.masked) 0x80 else 0));
            frame[index + 1] = @as(u8, @intCast((self.payload.len >> 8) & 0xFF));
            frame[index + 2] = @as(u8, @intCast(self.payload.len & 0xFF));
            index += 3;
        } else {
            frame[index] = 127 | (@as(u8, if (self.masked) 0x80 else 0));
            std.mem.writeInt(u64, frame[index + 1 .. index + 9][0..8], @as(u64, self.payload.len), .big);
            index += 9;
        }

        // Masking key
        if (self.masked) {
            if (self.masking_key) |mask| {
                @memcpy(frame[index .. index + 4], &mask);
            } else {
                // Generate random mask if not provided
                random.bytes(frame[index .. index + 4]);
            }
            index += 4;
        }

        // Payload (masked if needed)
        if (self.masked and self.masking_key != null) {
            const mask = self.masking_key.?;
            for (self.payload, 0..) |byte, i| {
                frame[index + i] = byte ^ mask[i % 4];
            }
        } else {
            @memcpy(frame[index .. index + self.payload.len], self.payload);
        }

        return frame;
    }

    /// Free any allocated memory for unmasked payload
    pub fn deinit(self: *WebSocketFrame, allocator: std.mem.Allocator) void {
        if (self.masked) {
            // Only free if we allocated memory for unmasking
            allocator.free(self.payload);
        }
    }

    pub fn toString(self: *const WebSocketFrame, allocator: std.mem.Allocator) ![]u8 {
        const opcode_name = switch (self.opcode) {
            .continuation => "continuation",
            .text => "text",
            .binary => "binary",
            .close => "close",
            .ping => "ping",
            .pong => "pong",
        };

        const payload_preview = if (self.payload.len > 0) blk: {
            const preview = try std.fmt.allocPrint(allocator, "\"{s}\"", .{self.payload[0..self.payload.len]});
            break :blk preview;
        } else "[]";
        defer if (self.payload.len > 0) allocator.free(payload_preview);

        const mask_str = if (self.masking_key) |mask| blk: {
            const mask_buf = try std.fmt.allocPrint(allocator, "[{x:0>2}{x:0>2}{x:0>2}{x:0>2}]", .{ mask[0], mask[1], mask[2], mask[3] });
            break :blk mask_buf;
        } else "none";
        defer if (self.masking_key != null) allocator.free(mask_str);

        return std.fmt.allocPrint(allocator, "WebSocketFrame{{ fin: {}, opcode: {s}, masked: {}, payload_len: {}, mask: {s}, payload: {s} }}", .{ self.fin, opcode_name, self.masked, self.payload.len, mask_str, payload_preview });
    }
};

// Keep the existing convenience functions but update them to use the struct
pub fn createTextFrame(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const frame = WebSocketFrame{
        .fin = true,
        .opcode = .text,
        .masked = true, // Client frames must be masked
        .payload = text,
    };
    return frame.serialize(allocator);
}

pub fn createControlFrame(allocator: std.mem.Allocator, op_code: WebSocketOpCode, payload: []const u8) ![]u8 {
    const frame = WebSocketFrame{
        .fin = true,
        .opcode = op_code,
        .masked = true, // Client frames must be masked
        .payload = payload,
    };
    return frame.serialize(allocator);
}

pub fn createCloseFrame(allocator: std.mem.Allocator) ![]u8 {
    return createControlFrame(allocator, .close, "");
}
