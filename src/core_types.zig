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
    disconnected,
    connecting,
    ready,
    closing,
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

pub const HttpRequest = struct {
    method: ?[]const u8 = null,
    path: ?[]const u8 = null,
    version: ?[]const u8 = null,
    host: ?[]const u8 = null,
    connection: ?[]const u8 = null,
    upgrade: ?[]const u8 = null,
    websocket_version: ?[]const u8 = null,
    websocket_key: ?[]const u8 = null,
};
