use serde::{Deserialize, Serialize};

pub const MAX_IPC_MESSAGE_SIZE: usize = 65536; // 64KB

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpcHeader {
    pub version: u32,
    pub message_id: String,
    pub session_id: String,
    pub msg_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChannelDetail {
    pub command: Option<String>,
    pub subsystem: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub allow_exec: bool,
    pub allow_port_forwarding: bool,
    pub terminal_encoding: String,
    pub idle_timeout_seconds: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum WorkerToService {
    #[serde(rename = "PONG")]
    Pong { data: String },
    #[serde(rename = "SESSION_STARTED")]
    SessionStarted { pid: u32 },
    #[serde(rename = "HEARTBEAT")]
    Heartbeat { load: f32 },
    #[serde(rename = "CHANNEL_OPENED")]
    ChannelOpened {
        channel_type: String,
        detail: ChannelDetail,
    },
    #[serde(rename = "AUDIT_EVENT")]
    AuditEvent {
        category: String,
        code: String,
        detail_json: String,
    },
    #[serde(rename = "SESSION_ENDED")]
    SessionEnded { result: String },
    #[serde(rename = "OUTPUT_DATA")]
    OutputData { data: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum ServiceToWorker {
    #[serde(rename = "PING")]
    Ping { data: String },
    #[serde(rename = "APPLY_POLICY")]
    ApplyPolicy {
        policy: Policy,
        _subsystem: Option<String>,
        command: Option<String>,
    },
    #[serde(rename = "TERMINATE_SESSION")]
    TerminateSession { reason: String },
    #[serde(rename = "UPDATE_LIMITS")]
    UpdateLimits {
        cpu_limit_percent: u32,
        memory_limit_mb: u32,
    },
    #[serde(rename = "DATA")]
    Data { data: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_serialization() {
        let policy = Policy {
            allow_exec: true,
            allow_port_forwarding: false,
            terminal_encoding: "utf-8".to_string(),
            idle_timeout_seconds: 3600,
        };
        let msg = ServiceToWorker::ApplyPolicy {
            policy,
            _subsystem: None,
            command: Some("whoami".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("APPLY_POLICY"));
        assert!(json.contains("whoami"));
        
        let decoded: ServiceToWorker = serde_json::from_str(&json).unwrap();
        if let ServiceToWorker::ApplyPolicy { command, .. } = decoded {
            assert_eq!(command, Some("whoami".to_string()));
        } else {
            panic!("Decoded wrong variant");
        }
    }
}
