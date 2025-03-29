pub const WebSocketOpCode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    ping = 0x9,
    pong = 0xA,
    close = 0x8,
};

pub const ConnectionState = enum {
    initial,
    handshake_sent,
    connected,
    closing,
};
