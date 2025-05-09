# Zig WebSocket Client

## Overview

This project implements a basic, non-blocking WebSocket client in the Zig programming language. It leverages the `xev` library for asynchronous I/O operations, providing a foundation for building applications that require real-time communication over WebSockets. The development process emphasizes learning Zig's features and low-level networking concepts.

## Goals

*   Implement a functional client compliant with core aspects of RFC 6455 (WebSocket Protocol).
*   Explore asynchronous I/O patterns in Zig using the `xev` event loop library.
*   Gain a practical understanding of the WebSocket handshake, framing, masking, and control frame handling (Ping/Pong, Close).
*   Develop a reasonably straightforward API for sending and receiving WebSocket messages.
*   Serve as an educational example for network programming and `xev` usage in Zig.

## Key Aspects

*   **Asynchronous Operations:** Built entirely on `xev` for non-blocking network I/O.
*   **WebSocket Handshake:** Performs the client-side HTTP upgrade request.
*   **Frame Parsing:** Decodes incoming Text, Binary, Close, Ping, and Pong frames.
*   **Frame Creation:** Encodes and masks outgoing Text, Close, Ping, and Pong frames.
*   **Control Frame Handling:** Automatically responds to server Pings with Pongs and handles the Close handshake.
*   **Write Queuing:** Includes logic to queue write operations initiated before the connection is fully established.

## Learning Outcomes

Developing this client provides hands-on experience with:

*   Event loop integration and asynchronous callbacks (`xev`).
*   Implementing a network protocol based on an RFC specification.
*   Manual buffer management and parsing binary data.
*   Memory management techniques (allocators, resource pooling).

## Getting Started

**(Instructions for building, integrating, and using the client library will be added as development progresses.)**

Example Usage (Conceptual):

```zig
const client = try Client.init(allocator, loop, server_address, myReadCallback);
try client.start();

// Later, once connected...
try client.write("Hello, WebSocket Server!");

fn myReadCallback(payload: []const u8) {
    std.debug.print("Received message: {s}\n", .{payload});
}
```

## Project Status

🚧 **Functional / Early Development** - The client can connect, perform the handshake, send/receive text messages, and handle basic Ping/Pong/Close control frames.

**Current Limitations:**

*   Does not support fragmented messages.
*   Limited configuration options.
*   Error handling and recovery strategies could be more robust.
*   Missing comprehensive tests.
