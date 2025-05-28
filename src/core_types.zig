const clnt = @import("client.zig");
const xev = @import("xev");

const Client = clnt.Client;

pub const WebSocketOpCode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    ping = 0x9,
    pong = 0xA,
    close = 0x8,
};

pub const QueuedWrite = struct {
    client: *Client,
    req: xev.WriteRequest = undefined,
    frame: []u8 = undefined,
};

pub const ConnectionState = enum {
    initial,
    connecting,
    tcp_connected,
    websocket_handshake_sent,
    websocket_connection_established,
    closing,
    closed,
};

pub const Error = error{
    UpgradeFailed,
    ReadError,
    WriteError,
    CloseError,
    ShutdownError,
    FramePayloadTooLarge,
    BufferTooSmall,
    EOF,
    ThreadPoolRequired,
    CanNotHandleFragmentedMessages,
    AlreadyConnected,
    ReceivedMaskedFrame,
    ReceivedOversizedFrame,
    ReceivedProtocolError,
    ReceivedInvalidOpcode,
    ReceivedFragmentedControlFrame,
    ReceivedOversizedControlFrame,
    ReceivedUnexpectedFrame,
    InvalidOpCode,
};
