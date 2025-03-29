const std = @import("std");
pub const FramePool = struct {
    allocator: std.mem.Allocator,
    buffers: std.ArrayList([]u8),
    used_count: usize,
    min_size: usize,

    pub fn init(allocator: std.mem.Allocator, count: usize, min_size: usize) !FramePool {
        var buffers = std.ArrayList([]u8).init(allocator);
        errdefer for (buffers.items) |b| allocator.free(b);
        for (0..count) |_| {
            const buffer = try allocator.alloc(u8, min_size);
            errdefer allocator.free(buffer);
            try buffers.append(buffer);
        }
        return .{
            .allocator = allocator,
            .buffers = buffers,
            .used_count = 0,
            .min_size = min_size,
        };
    }

    pub fn deinit(self: *FramePool) void {
        for (self.buffers.items) |buffer| {
            self.allocator.free(buffer);
        }
        self.buffers.deinit();
    }

    pub fn acquire(self: *FramePool, size: usize) ![]u8 {
        const max_size = size + (size / 4);
        var buffer_index: usize = self.used_count;
        var best_fit_index: ?usize = null;
        var best_fit_size: usize = std.math.maxInt(usize);

        while (buffer_index < self.buffers.items.len) : (buffer_index += 1) {
            const buffer = self.buffers.items[buffer_index];
            if (buffer.len >= size and buffer.len < best_fit_size) {
                best_fit_index = buffer_index;
                best_fit_size = buffer.len;
                if (buffer.len <= max_size) break;
            }
        }

        if (best_fit_index != null) {
            const index = best_fit_index.?;
            if (index != self.used_count) {
                const temp = self.buffers.items[self.used_count];
                self.buffers.items[self.used_count] = self.buffers.items[index];
                self.buffers.items[index] = temp;
            }
            self.used_count += 1;
            return self.buffers.items[self.used_count - 1][0..size];
        }

        const new_size = @max(size, self.min_size);
        const buffer = try self.allocator.alloc(u8, new_size);
        errdefer self.allocator.free(buffer);
        try self.buffers.insert(self.used_count, buffer);
        self.used_count += 1;
        return buffer[0..size];
    }

    pub fn release(self: *FramePool, buffer: []u8) void {
        for (self.buffers.items[0..self.used_count], 0..) |current, i| {
            if (current.ptr == buffer.ptr) {
                if (i != self.used_count - 1) {
                    const temp = self.buffers.items[self.used_count - 1];
                    self.buffers.items[self.used_count - 1] = current;
                    self.buffers.items[i] = temp;
                }
                self.used_count -= 1;
                return;
            }
        }
        unreachable;
    }
};
