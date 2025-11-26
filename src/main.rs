use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serialport::{available_ports, DataBits, Parity, SerialPort, SerialPortType, StopBits};
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, error, info, warn};
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
struct ToolDescription {
    name: String,
    description: String,
    input_schema: Value,
}

#[derive(Debug, Clone, Serialize)]
struct ToolListResult {
    tools: Vec<ToolDescription>,
}

#[derive(Debug, Deserialize)]
struct CallToolParams {
    name: String,
    arguments: Option<Value>,
}

#[derive(Debug, Serialize)]
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
            "serverInfo": {
                "name": "serial-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": {
                "tools": tool_list_schema().tools,
            }
        }),
    )
}

fn main() {
    let config = Config::from_env();
    tracing_subscriber::fmt()
        .with_env_filter(config.log_level.as_str())
        .with_writer(std::io::stderr)
        .init();

    info!("Starting serial-mcp server");
    let manager = SessionManager::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = stdin.lock();

    let tool_schemas = tool_list_schema();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(err) => {
                error!("Failed to read stdin: {err}");
                break;
            }
        };

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

        if let Err(err) = writeln!(stdout, "{}", serde_json::to_string(&response).unwrap()) {
            error!("Failed to write response: {err}");
            break;
        }

        if let Err(err) = stdout.flush() {
            error!("Failed to flush response: {err}");
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
