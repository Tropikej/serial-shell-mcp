1. Purpose & Scope

The serial-mcp server is a Model Context Protocol (MCP) server that allows Codex (or any MCP client) to interact with serial COM ports on Windows 11.

It provides:

Enumeration of available COM ports.

Opening a serial connection to a chosen COM port.

Reading data from the port (UART logs, shell output).

Sending text commands over UART.

Cleanly disconnecting from ports.

The MCP server communicates with clients via JSON-RPC over stdin/stdout, as per MCP conventions.

2. Target Environment

OS: Windows 11 (64-bit).

Language: Rust (stable).

Serial library: serialport
.

Runtime: Single binary (e.g. serial-mcp.exe).

No cross-platform support is required in v1, but design should not intentionally block future Linux/macOS support.

3. Core Concepts
3.1 Port

A port is a Windows COM device, e.g. COM3, COM5, representing a UART interface (e.g. STM32 virtual COM port).

3.2 Session

A session is an open serial connection to a specific port with specific parameters (baud rate, data bits, etc.).

Each session has a session_id (string, UUID-like).

Multiple sessions may be open concurrently (e.g. COM3 and COM5), but only one session per port is allowed by default to avoid conflicts.

3.3 Data model

Data sent/received is treated as UTF-8 text by default.

Internally it is byte-based; non-UTF-8 data must be handled gracefully (lossy conversion allowed).

4. Functional Requirements
4.1 Enumerate available COM ports

The server must provide a tool serial_list_ports that:

Lists all available serial ports (COMx) on the system.

Returns, for each:

name: the COM port name, e.g. "COM3".

description: human-readable description when available (e.g. “STLink Virtual COM Port”).

If no ports are available, returns an empty list (not an error).

4.2 Connect to an available COM port

Tool: serial_connect.

Inputs:

port (string): required; e.g. "COM3".

baud (integer, default 115200).

data_bits (integer, default 8, allowed: 5,6,7,8).

stop_bits (number, default 1, allowed: 1, 1.5, 2).

parity (string, default "none", allowed: "none", "even", "odd").

timeout_ms (integer, default 100): read timeout for underlying port.

Behavior:

If port is already in use by an existing session:

Either:

return an error PORT_ALREADY_IN_USE, or

optionally allow a force flag in the future.

On success:

Open the port with given parameters.

Store it in an in-memory session map.

Return a session_id for subsequent operations.

Output:

session_id: string.

port: string.

baud, data_bits, stop_bits, parity.

4.3 Disconnect from a COM port

Tool: serial_disconnect.

Inputs:

session_id (string): required.

Behavior:

Look up the session by session_id.

Close the underlying serial port.

Remove the session from the internal map.

If the session doesn’t exist, return UNKNOWN_SESSION.

Output:

success: boolean.

message: optional human-readable info.

4.4 Send text over UART

Tool: serial_send.

Inputs:

session_id (string): required.

data (string): text to send.

append_newline (boolean, default true):

If true, append "\n" (or "\r\n" configurable) to emulate terminal Enter.

Behavior:

Convert text to bytes using UTF-8.

Append newline if requested.

Write bytes to the port.

Return number of bytes actually written.

Output:

bytes_written: integer.

Error conditions:

Unknown session_id → UNKNOWN_SESSION.

Write failure → WRITE_ERROR with message from OS.

4.5 Read from UART

Tool: serial_read.

Inputs:

session_id (string): required.

max_bytes (integer, default 1024, min 1, max e.g. 65536).

timeout_ms (integer, optional; if omitted, use session default).

Behavior:

Perform a blocking read with timeout on the serial port.

If data is received:

Return up to max_bytes.

If timeout occurs with no data:

Return timed_out = true and empty data.

Output:

data (string): decoded from bytes as UTF-8 (lossy allowed).

bytes_read (integer).

timed_out (boolean).

Error conditions:

Unknown session → UNKNOWN_SESSION.

Read error (e.g. device disconnected) → READ_ERROR.

5. Non-Functional Requirements
5.1 Performance

Meant for human-speed UART, not high-throughput binary streaming.

Must handle typical microcontroller UART speeds: 9600–115200 baud (up to 921600 may still be fine).

serial_read with small timeout_ms should be efficient enough not to freeze the MCP.

5.2 Concurrency

Multiple MCP tool invocations may run concurrently.

Internal session map must be synchronized (e.g. Arc<Mutex<...>>).

Only one thread should read/write a given session’s port at a time:

Either enforce sequential read/write calls, or have separate lock per session.

5.3 Reliability

If a port disappears (USB unplugged):

The next read/write on that session should return a clean error (DEVICE_DISCONNECTED) instead of panicking.

Optionally mark session as closed internally.

6. MCP Manifest (mcp.json)

Example mcp.json for the server:

{
  "name": "serial-mcp",
  "version": "1.0.0",
  "description": "MCP server that provides access to serial COM ports on Windows (UART console for MCUs).",
  "tools": [
    {
      "name": "serial_list_ports",
      "description": "List available serial COM ports on this Windows machine.",
      "inputSchema": {
        "type": "object",
        "properties": {}
      }
    },
    {
      "name": "serial_connect",
      "description": "Open a serial session to a COM port with given parameters.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "port": {
            "type": "string",
            "description": "COM port name, e.g. 'COM3'."
          },
          "baud": {
            "type": "integer",
            "description": "Baud rate, e.g. 115200.",
            "default": 115200
          },
          "data_bits": {
            "type": "integer",
            "description": "Number of data bits (5, 6, 7, or 8).",
            "default": 8
          },
          "stop_bits": {
            "type": "number",
            "description": "Stop bits (1, 1.5, or 2).",
            "default": 1
          },
          "parity": {
            "type": "string",
            "description": "Parity mode.",
            "enum": ["none", "even", "odd"],
            "default": "none"
          },
          "timeout_ms": {
            "type": "integer",
            "description": "Read timeout in milliseconds (session default).",
            "default": 100
          }
        },
        "required": ["port"]
      }
    },
    {
      "name": "serial_disconnect",
      "description": "Close an open serial session and release the COM port.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "session_id": {
            "type": "string",
            "description": "ID of the session to close."
          }
        },
        "required": ["session_id"]
      }
    },
    {
      "name": "serial_send",
      "description": "Send text data over an open serial session.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "session_id": {
            "type": "string",
            "description": "Target serial session."
          },
          "data": {
            "type": "string",
            "description": "Text to send over UART."
          },
          "append_newline": {
            "type": "boolean",
            "description": "Append newline at the end of the data.",
            "default": true
          }
        },
        "required": ["session_id", "data"]
      }
    },
    {
      "name": "serial_read",
      "description": "Read data from an open serial session.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "session_id": {
            "type": "string",
            "description": "Target serial session."
          },
          "max_bytes": {
            "type": "integer",
            "description": "Maximum number of bytes to read.",
            "default": 1024
          },
          "timeout_ms": {
            "type": "integer",
            "description": "Read timeout in milliseconds. If omitted, use session default."
          }
        },
        "required": ["session_id"]
      }
    }
  ]
}

7. Internal Architecture
7.1 Process Model

serial-mcp.exe is spawned by Codex according to config.toml.

Communication with Codex:

JSON-RPC over stdin/stdout as specified by MCP.

On startup:

Load configuration (environment variables / optional config file).

Initialize global state.

Enter MCP main loop.

7.2 Global State

Define a State struct:

struct SerialSession {
    port_name: String,
    baud: u32,
    data_bits: u8,
    stop_bits: f32,
    parity: Parity,
    timeout_ms: u64,
    port: Box<dyn serialport::SerialPort>, // thread-safe access via Mutex
}

struct State {
    sessions: HashMap<String, SerialSession>, // session_id -> session
}


Wrapped in Arc<Mutex<State>> for concurrent access.

Each tool handler receives a clone of Arc<Mutex<State>>.

7.3 Tool Handlers

Each MCP tool corresponds to a Rust handler function:

handle_serial_list_ports(state, args) -> result_json

handle_serial_connect(state, args) -> result_json

etc.

Error handling:

Explicit error types for known conditions:

UNKNOWN_SESSION

PORT_ALREADY_IN_USE

OPEN_ERROR

READ_ERROR

WRITE_ERROR

INVALID_ARGUMENT

Map them to JSON-RPC error objects with code and message.

8. Configuration
8.1 Environment Variables

Support optional environment variables:

SERIAL_MCP_DEFAULT_BAUD (e.g. 115200).

SERIAL_MCP_DEFAULT_TIMEOUT_MS (e.g. 100).

SERIAL_MCP_LOG_LEVEL (error, warn, info, debug, trace).

If not set, fall back to built-in defaults.

8.2 Codex config.toml Example

For Codex:

[[mcp.servers]]
id = "serial-mcp"
command = "C:\\Tools\\serial-mcp.exe"
args = []
auto_start = true

9. Logging & Diagnostics

Use a logging crate (tracing or log + env_logger).

Log (at info or debug):

MCP start / stop.

Calls to tools with parameters (mask sensitive info if any).

Port open / close events.

Errors from OS (e.g. failed to open COM3).

Optionally expose a serial_list_sessions tool (debug only) to see active sessions and their config.

10. Security Considerations

This MCP exposes direct access to local serial devices.

Assumptions:

The user running Codex trusts themselves; no multi-user security model.

Potential measures:

Restrict allowed ports via env var, e.g. SERIAL_MCP_ALLOWED_PORTS=COM3,COM4.

Optionally reject sending certain patterns (e.g. if you later expose bootloader commands you consider dangerous).

In your own dev setup you probably don’t need heavy restrictions, but the spec leaves room for them.

11. UX Expectations From Codex Side

From inside Codex, a typical usage flow:

List ports

Call serial_list_ports.

Display available ports to the user.

Connect to STM32

Call serial_connect with port="COM3", baud=115200.

Store session_id in conversation context.

Read logs

Poll serial_read(session_id, max_bytes=1024, timeout_ms=200) to get UART output.

Display it in conversation.

Send commands

Call serial_send(session_id, "help").

Then serial_read again to capture the response.

Disconnect

Call serial_disconnect(session_id) when done.

12. Future Extensions (Out of Scope v1, but nice to note)

Binary mode:

Tools for sending/receiving raw bytes as base64, for bootloaders or binary protocols.

Line-oriented mode:

serial_read_line that reads until \n or timeout.

Event streaming:

A “push” style mechanism to stream UART output as events, instead of polling serial_read.

Profiles:

Saved configurations per board (e.g. “STM32-Board-1 → COM3@115200, no parity”).