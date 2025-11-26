# serial-mcp

A Model Context Protocol (MCP) server that exposes Windows serial COM ports to Codex or any MCP-compatible client via JSON-RPC over stdin/stdout.

## Features
- Enumerate available COM ports.
- Open and manage multiple serial sessions (one per port) with configurable baud, data bits, stop bits, parity, and timeouts.
- Send UTF-8, hex, or base64 encoded payloads to a port.
- Read from an open port with configurable byte limits and timeouts.
- Disconnect sessions and inspect active connections for diagnostics.
- Optional port-allow list and runtime configuration via environment variables.
- Structured logging with `tracing`.

## Building
The server targets Windows 11 and produces a single executable binary.

```bash
# Build release binary (on Windows)
cargo build --release
# Expected output: target/release/serial-shell-mcp.exe
```

To cross-compile for Windows from another host with the MSVC toolchain installed:

```bash
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
# Output: target/x86_64-pc-windows-msvc/release/serial-shell-mcp.exe
```

## Running
The server communicates over stdin/stdout using JSON-RPC 2.0.

```bash
./target/release/serial-shell-mcp.exe
```

Tooling methods follow MCP conventions:
- `initialize`: returns server info and advertised tools.
- `list_tools` / `tools/list`: returns tool schemas.
- `call_tool` / `tools/call`: execute a tool with `name` and `arguments`.

### Available tools
- `serial_list_ports` – list COM ports with optional descriptions.
- `serial_connect` – open a port and create a session (returns `session_id`).
- `serial_disconnect` – close a session by `session_id`.
- `serial_read` – read up to `max_bytes` bytes with optional `timeout_ms` override.
- `serial_send` – send data with optional `encoding` (`utf-8`, `hex`, `base64`).
- `serial_list_sessions` – debug helper to list active sessions.
  - Note: the underlying serial library supports one or two stop bits; a request for 1.5 stop bits is accepted but coerced to two stop bits, and a warning is logged.

### Example payloads
List tools:
```json
{"jsonrpc":"2.0","id":1,"method":"list_tools"}
```

Connect to `COM3`:
```json
{
  "jsonrpc":"2.0",
  "id":2,
  "method":"call_tool",
  "params":{
    "name":"serial_connect",
    "arguments":{"port":"COM3","baud":115200}
  }
}
```

Send text:
```json
{
  "jsonrpc":"2.0",
  "id":3,
  "method":"call_tool",
  "params":{
    "name":"serial_send",
    "arguments":{"session_id":"<returned-id>","data":"help"}
  }
}
```

Read:
```json
{
  "jsonrpc":"2.0",
  "id":4,
  "method":"call_tool",
  "params":{
    "name":"serial_read",
    "arguments":{"session_id":"<returned-id>","max_bytes":512,"timeout_ms":200}
  }
}
```

Disconnect:
```json
{"jsonrpc":"2.0","id":5,"method":"call_tool","params":{"name":"serial_disconnect","arguments":{"session_id":"<returned-id>"}}}
```

## Configuration
Environment variables override defaults:
- `SERIAL_MCP_DEFAULT_BAUD` (default `115200`)
- `SERIAL_MCP_DEFAULT_TIMEOUT_MS` (default `100`)
- `SERIAL_MCP_LOG_LEVEL` (`error`, `warn`, `info`, `debug`, `trace`; default `info`)
- `SERIAL_MCP_ALLOWED_PORTS` (comma-separated allow list such as `COM3,COM4`)

## Codex configuration example
Add to `config.toml`:
```toml
[[mcp.servers]]
id = "serial-mcp"
command = "C:\\Tools\\serial-shell-mcp.exe"
args = []
auto_start = true
```

## Security considerations
- Optionally restrict access to specific ports via `SERIAL_MCP_ALLOWED_PORTS`.
- Logs include tool calls and port lifecycle events for auditing.
- Binary/line-streaming extensions can be added later without breaking the current API.
