use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{error::Category, json, Value};
use serialport::{available_ports, DataBits, Parity, SerialPort, SerialPortType, StopBits};
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Debug, Clone)]
struct Config {
    default_baud: u32,
    default_timeout_ms: u64,
    log_level: String,
    allowed_ports: Option<HashSet<String>>,
}

impl Config {
    fn from_env() -> Self {
        let default_baud = std::env::var("SERIAL_MCP_DEFAULT_BAUD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(115_200);

        let default_timeout_ms = std::env::var("SERIAL_MCP_DEFAULT_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let log_level = std::env::var("SERIAL_MCP_LOG_LEVEL")
            .ok()
            .unwrap_or_else(|| "info".to_string());

        let allowed_ports = std::env::var("SERIAL_MCP_ALLOWED_PORTS").ok().map(|v| {
            v.split(',')
                .filter_map(|p| {
                    let trimmed = p.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_uppercase())
                    }
                })
                .collect::<HashSet<_>>()
        });

        Self {
            default_baud,
            default_timeout_ms,
            log_level,
            allowed_ports,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolDescription {
    name: String,
    description: String,
    input_schema: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolListResult {
    tools: Vec<ToolDescription>,
}

#[derive(Debug, Deserialize)]
struct CallToolParams {
    name: String,
    arguments: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CallToolResult {
    content: Vec<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_error: Option<bool>,
}

#[derive(Debug, Serialize)]
struct Content {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

#[derive(Debug)]
struct Session {
    info: SessionInfo,
    port: Mutex<Box<dyn SerialPort>>,
}

#[derive(Debug, Clone, Serialize)]
struct SessionInfo {
    session_id: String,
    port: String,
    baud: u32,
    data_bits: u8,
    stop_bits: f32,
    parity: String,
    timeout_ms: u64,
}

#[derive(Debug, Serialize)]
struct PortEntry {
    name: String,
    description: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("Unknown session")]
    UnknownSession,
    #[error("Port already in use")]
    PortAlreadyInUse,
    #[error("Failed to open port: {0}")]
    OpenError(String),
    #[error("Read error: {0}")]
    ReadError(String),
    #[error("Write error: {0}")]
    WriteError(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Access to port denied by policy")]
    PortDenied,
}

impl ServerError {
    fn code(&self) -> i32 {
        match self {
            ServerError::UnknownSession => -32001,
            ServerError::PortAlreadyInUse => -32002,
            ServerError::OpenError(_) => -32003,
            ServerError::ReadError(_) => -32004,
            ServerError::WriteError(_) => -32005,
            ServerError::InvalidArgument(_) => -32602,
            ServerError::PortDenied => -32006,
        }
    }
}

struct SessionManager {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}

impl SessionManager {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn list_sessions(&self) -> Vec<SessionInfo> {
        let guard = self.sessions.lock().unwrap();
        guard.values().map(|s| s.info.clone()).collect()
    }

    fn port_in_use(&self, port: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .any(|s| s.info.port.eq_ignore_ascii_case(port))
    }

    fn insert(&self, session: Session) -> String {
        let id = session.info.session_id.clone();
        self.sessions
            .lock()
            .unwrap()
            .insert(id.clone(), Arc::new(session));
        id
    }

    fn remove(&self, session_id: &str) -> Result<SessionInfo, ServerError> {
        let removed = self.sessions.lock().unwrap().remove(session_id);
        removed
            .map(|s| s.info.clone())
            .ok_or(ServerError::UnknownSession)
    }

    fn get(&self, session_id: &str) -> Result<Arc<Session>, ServerError> {
        self.sessions
            .lock()
            .unwrap()
            .get(session_id)
            .cloned()
            .ok_or(ServerError::UnknownSession)
    }
}

fn parse_data_bits(bits: u8) -> Result<DataBits, ServerError> {
    match bits {
        5 => Ok(DataBits::Five),
        6 => Ok(DataBits::Six),
        7 => Ok(DataBits::Seven),
        8 => Ok(DataBits::Eight),
        v => Err(ServerError::InvalidArgument(format!(
            "Unsupported data bits: {v}"
        ))),
    }
}

fn parse_stop_bits(value: f32) -> Result<StopBits, ServerError> {
    if (value - 1.0).abs() < f32::EPSILON {
        Ok(StopBits::One)
    } else if (value - 1.5).abs() < f32::EPSILON {
        warn!("1.5 stop bits requested; using two stop bits as the closest supported value");
        Ok(StopBits::Two)
    } else if (value - 2.0).abs() < f32::EPSILON {
        Ok(StopBits::Two)
    } else {
        Err(ServerError::InvalidArgument(format!(
            "Unsupported stop bits: {value}"
        )))
    }
}

fn parse_parity(value: &str) -> Result<Parity, ServerError> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(Parity::None),
        "even" => Ok(Parity::Even),
        "odd" => Ok(Parity::Odd),
        other => Err(ServerError::InvalidArgument(format!(
            "Unsupported parity: {other}"
        ))),
    }
}

#[derive(Debug, Deserialize)]
struct ConnectParams {
    port: String,
    #[serde(default)]
    baud: Option<u32>,
    #[serde(default)]
    data_bits: Option<u8>,
    #[serde(default)]
    stop_bits: Option<f32>,
    #[serde(default)]
    parity: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ConnectResult {
    session_id: String,
    port: String,
    baud: u32,
    data_bits: u8,
    stop_bits: f32,
    parity: String,
    timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
struct SessionParams {
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct SendParams {
    session_id: String,
    data: String,
    #[serde(default)]
    encoding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReadParams {
    session_id: String,
    #[serde(default = "default_max_bytes")]
    max_bytes: usize,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

fn default_max_bytes() -> usize {
    1024
}

fn serialize_ports() -> Vec<PortEntry> {
    match available_ports() {
        Ok(ports) => ports
            .into_iter()
            .map(|p| PortEntry {
                name: p.port_name,
                description: match p.port_type {
                    SerialPortType::UsbPort(info) => info.product,
                    SerialPortType::BluetoothPort => Some("Bluetooth".to_string()),
                    SerialPortType::PciPort => Some("PCI".to_string()),
                    SerialPortType::Unknown => None,
                },
            })
            .collect(),
        Err(err) => {
            warn!("Failed to enumerate ports: {err}");
            vec![]
        }
    }
}

fn text_content(text: impl Into<String>) -> Content {
    Content {
        content_type: "text".to_string(),
        text: text.into(),
    }
}

#[cfg(windows)]
fn configure_stdio_binary() {
    const O_BINARY: i32 = 0x8000;
    const STDIN_FILENO: i32 = 0;
    const STDOUT_FILENO: i32 = 1;

    unsafe {
        extern "C" {
            fn _setmode(fd: i32, mode: i32) -> i32;
        }

        if _setmode(STDIN_FILENO, O_BINARY) == -1 {
            eprintln!("Failed to set stdin binary mode");
        }
        if _setmode(STDOUT_FILENO, O_BINARY) == -1 {
            eprintln!("Failed to set stdout binary mode");
        }
    }
}

#[cfg(not(windows))]
fn configure_stdio_binary() {}

#[derive(Clone, Copy, Debug)]
enum FrameStyle {
    Http,
    Raw,
}

fn read_message(reader: &mut impl BufRead) -> io::Result<Option<(String, FrameStyle)>> {
    loop {
        let Some(first_byte) = peek_first_non_whitespace(reader)? else {
            return Ok(None);
        };

        if first_byte == b'{' || first_byte == b'[' {
            return read_unframed_json(reader).map(|msg| Some((msg, FrameStyle::Raw)));
        }

        let mut line = String::new();
        let mut content_length: Option<usize> = None;

        loop {
            line.clear();
            let read = reader.read_line(&mut line)?;
            if read == 0 {
                return if content_length.is_some() {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream closed mid-frame",
                    ))
                } else {
                    Ok(None)
                };
            }

            let trimmed = line.trim();

            if trimmed.is_empty() {
                if let Some(len) = content_length {
                    let mut buf = vec![0u8; len];
                    reader.read_exact(&mut buf)?;
                    let message = String::from_utf8(buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    return Ok(Some((message, FrameStyle::Http)));
                }

                continue;
            }

            if let Some(first_char) = trimmed.chars().next() {
                if first_char == '{' || first_char == '[' {
                    return Ok(Some((trimmed.to_string(), FrameStyle::Raw)));
                }
            }

            if let Some((name, value)) = trimmed.split_once(':') {
                let name = name.trim();
                let value = value.trim();

                if name.eq_ignore_ascii_case("content-length") {
                    content_length = Some(
                        value
                            .parse()
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                    );
                }

                continue;
            }

            return Ok(Some((trimmed.to_string(), FrameStyle::Raw)));
        }
    }
}

fn peek_first_non_whitespace(reader: &mut impl BufRead) -> io::Result<Option<u8>> {
    let mut bom_checked = false;

    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(None);
        }

        if !bom_checked && buffer.len() >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF {
            reader.consume(3);
            bom_checked = true;
            continue;
        }
        bom_checked = true;

        let mut offset = 0;
        while offset < buffer.len() {
            let byte = buffer[offset];
            if byte.is_ascii_whitespace() {
                offset += 1;
                continue;
            }

            if offset > 0 {
                reader.consume(offset);
            }
            return Ok(Some(byte));
        }

        reader.consume(offset);
    }
}

fn read_unframed_json(reader: &mut impl BufRead) -> io::Result<String> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        match serde_json::from_slice::<Value>(&buffer) {
            Ok(value) => {
                return serde_json::to_string(&value)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
            }
            Err(err) => {
                if err.classify() != Category::Eof {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, err));
                }
            }
        }

        reader.read_exact(&mut byte)?;
        buffer.push(byte[0]);
    }
}

fn write_json_response_with_frame(
    stdout: &mut impl Write,
    response: &Value,
    frame: FrameStyle,
) -> io::Result<()> {
    let payload = serde_json::to_string(response)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    match frame {
        FrameStyle::Http => {
            let header = format!(
                "Content-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                payload.as_bytes().len()
            );
            stdout.write_all(header.as_bytes())?;
            stdout.write_all(payload.as_bytes())?;
        }
        FrameStyle::Raw => {
            stdout.write_all(payload.as_bytes())?;
            stdout.write_all(b"\n")?;
        }
    }

    stdout.flush()
}

fn connect(
    manager: &SessionManager,
    params: ConnectParams,
    config: &Config,
) -> Result<ConnectResult, ServerError> {
    let port_name = params.port;
    let normalized_port = port_name.to_uppercase();

    if let Some(allowed) = &config.allowed_ports {
        if !allowed.contains(&normalized_port) {
            return Err(ServerError::PortDenied);
        }
    }

    if manager.port_in_use(&port_name) {
        return Err(ServerError::PortAlreadyInUse);
    }

    let baud = params.baud.unwrap_or(config.default_baud);
    let data_bits_value = params.data_bits.unwrap_or(8);
    let data_bits = parse_data_bits(data_bits_value)?;
    let stop_bits_value = params.stop_bits.unwrap_or(1.0);
    let stop_bits = parse_stop_bits(stop_bits_value)?;
    let parity_value = params.parity.unwrap_or_else(|| "none".to_string());
    let parity = parse_parity(&parity_value)?;
    let timeout_ms = params.timeout_ms.unwrap_or(config.default_timeout_ms);

    let builder = serialport::new(&port_name, baud)
        .data_bits(data_bits)
        .stop_bits(stop_bits)
        .parity(parity)
        .timeout(Duration::from_millis(timeout_ms));

    info!("Opening serial port {port_name} at {baud} baud");
    let port = builder
        .open()
        .map_err(|e| ServerError::OpenError(e.to_string()))?;

    let session_id = Uuid::new_v4().to_string();
    let info = SessionInfo {
        session_id: session_id.clone(),
        port: port_name.clone(),
        baud,
        data_bits: data_bits_value,
        stop_bits: stop_bits_value,
        parity: parity_value.clone(),
        timeout_ms,
    };

    manager.insert(Session {
        info: info.clone(),
        port: Mutex::new(port),
    });

    Ok(ConnectResult {
        session_id,
        port: port_name,
        baud,
        data_bits: data_bits_value,
        stop_bits: stop_bits_value,
        parity: parity_value,
        timeout_ms,
    })
}

fn disconnect(manager: &SessionManager, params: SessionParams) -> Result<SessionInfo, ServerError> {
    manager.remove(&params.session_id)
}

fn decode_payload(data: &str, encoding: Option<&str>) -> Result<Vec<u8>, ServerError> {
    match encoding.unwrap_or("utf-8").to_ascii_lowercase().as_str() {
        "utf-8" | "utf8" => Ok(data.as_bytes().to_vec()),
        "hex" => hex::decode(data).map_err(|e| ServerError::InvalidArgument(e.to_string())),
        "base64" => general_purpose::STANDARD
            .decode(data)
            .map_err(|e| ServerError::InvalidArgument(e.to_string())),
        other => Err(ServerError::InvalidArgument(format!(
            "Unsupported encoding: {other}"
        ))),
    }
}

fn send(manager: &SessionManager, params: SendParams) -> Result<usize, ServerError> {
    let session = manager.get(&params.session_id)?;
    let bytes = decode_payload(&params.data, params.encoding.as_deref())?;

    let mut guard = session.port.lock().unwrap();
    guard
        .write(&bytes)
        .map_err(|e| ServerError::WriteError(e.to_string()))
}

fn read(manager: &SessionManager, params: ReadParams) -> Result<Vec<u8>, ServerError> {
    let session = manager.get(&params.session_id)?;
    let mut guard = session.port.lock().unwrap();

    if let Some(timeout) = params.timeout_ms {
        let _ = guard.set_timeout(Duration::from_millis(timeout));
    }

    let mut buffer = vec![0u8; params.max_bytes];
    match guard.read(buffer.as_mut_slice()) {
        Ok(size) => {
            buffer.truncate(size);
            Ok(buffer)
        }
        Err(err) => {
            if err.kind() == io::ErrorKind::TimedOut {
                Ok(Vec::new())
            } else {
                Err(ServerError::ReadError(err.to_string()))
            }
        }
    }
}

fn render_error_response(id: Value, error: &ServerError) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": error.code(),
            "message": error.to_string(),
        }
    })
}

fn render_ok_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

fn tool_list_schema() -> ToolListResult {
    let tools = vec![
        ToolDescription {
            name: "serial_list_ports".to_string(),
            description: "List available serial COM ports.".to_string(),
            input_schema: json!({"type": "object", "properties": {}, "required": []}),
        },
        ToolDescription {
            name: "serial_connect".to_string(),
            description: "Open a serial connection to a COM port.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "port": {"type": "string", "description": "COM port name (e.g. COM3)."},
                    "baud": {"type": "integer", "description": "Baud rate", "default": 115200},
                    "data_bits": {"type": "integer", "enum": [5,6,7,8], "default": 8},
                    "stop_bits": {"type": "number", "enum": [1.0, 1.5, 2.0], "default": 1.0},
                    "parity": {"type": "string", "enum": ["none","even","odd"], "default": "none"},
                    "timeout_ms": {"type": "integer", "description": "Read timeout in ms", "default": 100}
                },
                "required": ["port"]
            }),
        },
        ToolDescription {
            name: "serial_disconnect".to_string(),
            description: "Disconnect an active serial session.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"}
                },
                "required": ["session_id"]
            }),
        },
        ToolDescription {
            name: "serial_read".to_string(),
            description: "Read bytes from an open serial session.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "max_bytes": {"type": "integer", "default": 1024},
                    "timeout_ms": {"type": "integer", "description": "Override read timeout"}
                },
                "required": ["session_id"]
            }),
        },
        ToolDescription {
            name: "serial_send".to_string(),
            description: "Send bytes to an open serial session.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "data": {"type": "string", "description": "Payload to send (text, hex, or base64)."},
                    "encoding": {"type": "string", "enum": ["utf-8", "hex", "base64"], "default": "utf-8"}
                },
                "required": ["session_id", "data"]
            }),
        },
        ToolDescription {
            name: "serial_list_sessions".to_string(),
            description: "List active serial sessions (debug).".to_string(),
            input_schema: json!({"type": "object", "properties": {}, "required": []}),
        },
    ];

    ToolListResult { tools }
}

fn initialize_response(id: Value) -> Value {
    render_ok_response(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "serial-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": {
                "tools": {
                    // Advertise that the server supports listing and calling tools
                    // via the standard MCP tool APIs. The actual tool schemas are
                    // returned by the list_tools/tools/list method.
                    "listChanged": false,
                },
            }
        }),
    )
}

fn main() {
    configure_stdio_binary();
    let config = Config::from_env();
    let env_filter = EnvFilter::try_new(config.log_level.as_str()).unwrap_or_else(|err| {
        eprintln!(
            "Invalid SERIAL_MCP_LOG_LEVEL '{}': {err}; falling back to 'info'",
            config.log_level
        );
        EnvFilter::new("info")
    });

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();

    info!("Starting serial-mcp server");
    let manager = SessionManager::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());

    let tool_schemas = tool_list_schema();

    loop {
        let message = match read_message(&mut reader) {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                error!("Invalid JSON: {err}");
                continue;
            }
            Err(err) => {
                error!("Failed to read stdin: {err}");
                break;
            }
        };

        let (line, frame) = message;

        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(err) => {
                error!("Invalid JSON: {err}");
                continue;
            }
        };

        if request.get("id").is_none() {
            if let Some(method) = request.get("method").and_then(|v| v.as_str()) {
                info!("Received notification '{method}', ignoring");
            } else {
                warn!("Received notification without method");
            }
            continue;
        }

        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = match request.get("method").and_then(|v| v.as_str()) {
            Some(m) => m,
            None => {
                let response = render_error_response(
                    id,
                    &ServerError::InvalidArgument("Missing method".into()),
                );
                writeln!(stdout, "{}", serde_json::to_string(&response).unwrap()).ok();
                stdout.flush().ok();
                continue;
            }
        };

        debug!("Handling method {method}");
        let params = request.get("params").cloned().unwrap_or(json!({}));

        let response = match method {
            "initialize" => initialize_response(id),
            "list_tools" | "tools/list" => {
                render_ok_response(id, serde_json::to_value(&tool_schemas).unwrap())
            }
            "call_tool" | "tools/call" => match serde_json::from_value::<CallToolParams>(params) {
                Ok(call) => match dispatch_tool(&manager, call, &config) {
                    Ok(result) => render_ok_response(id, serde_json::to_value(result).unwrap()),
                    Err(err) => render_error_response(id, &err),
                },
                Err(err) => render_error_response(
                    id,
                    &ServerError::InvalidArgument(format!("Invalid params: {err}")),
                ),
            },
            _ => render_error_response(id, &ServerError::InvalidArgument("Unknown method".into())),
        };

        if let Err(err) = write_json_response_with_frame(&mut stdout, &response, frame) {
            error!("Failed to write response: {err}");
            break;
        }
    }
}

fn dispatch_tool(
    manager: &SessionManager,
    call: CallToolParams,
    config: &Config,
) -> Result<CallToolResult, ServerError> {
    match call.name.as_str() {
        "serial_list_ports" => {
            let ports = serialize_ports();
            let text = serde_json::to_string_pretty(&ports).unwrap_or_default();
            Ok(CallToolResult {
                content: vec![text_content(text)],
                is_error: None,
            })
        }
        "serial_connect" => {
            let params: ConnectParams = serde_json::from_value(call.arguments.unwrap_or_default())
                .map_err(|e| ServerError::InvalidArgument(e.to_string()))?;
            let result = connect(manager, params, config)?;
            Ok(CallToolResult {
                content: vec![text_content(
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                )],
                is_error: None,
            })
        }
        "serial_disconnect" => {
            let params: SessionParams = serde_json::from_value(call.arguments.unwrap_or_default())
                .map_err(|e| ServerError::InvalidArgument(e.to_string()))?;
            let info = disconnect(manager, params)?;
            Ok(CallToolResult {
                content: vec![text_content(format!("Disconnected {}", info.session_id))],
                is_error: None,
            })
        }
        "serial_send" => {
            let params: SendParams = serde_json::from_value(call.arguments.unwrap_or_default())
                .map_err(|e| ServerError::InvalidArgument(e.to_string()))?;
            let written = send(manager, params)?;
            Ok(CallToolResult {
                content: vec![text_content(format!("Wrote {written} bytes"))],
                is_error: None,
            })
        }
        "serial_read" => {
            let params: ReadParams = serde_json::from_value(call.arguments.unwrap_or_default())
                .map_err(|e| ServerError::InvalidArgument(e.to_string()))?;
            let data = read(manager, params)?;
            let preview = match String::from_utf8(data.clone()) {
                Ok(text) => text,
                Err(_) => hex::encode(&data),
            };
            Ok(CallToolResult {
                content: vec![text_content(preview)],
                is_error: None,
            })
        }
        "serial_list_sessions" => {
            let sessions = manager.list_sessions();
            Ok(CallToolResult {
                content: vec![text_content(
                    serde_json::to_string_pretty(&sessions).unwrap_or_default(),
                )],
                is_error: None,
            })
        }
        _ => Err(ServerError::InvalidArgument("Unknown tool".into())),
    }
}
