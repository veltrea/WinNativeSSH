use serde::{Deserialize, Serialize};

pub mod handler;
pub mod protocol;

pub use protocol::SBPRequest;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InternalCommand {
    UpgradeSBP { version: String },
    ExecJson,
    SbpSpec,
}

impl InternalCommand {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        match parts[0].to_lowercase().as_str() {
            "upgrade-sbp" => {
                let version = if parts.len() > 1 {
                    parts[1].to_string()
                } else {
                    "v1".to_string() // Default to v1 if not specified for backward compatibility
                };
                Some(InternalCommand::UpgradeSBP { version })
            }
            "vlt-ssh-json" => Some(InternalCommand::ExecJson),
            "sbp-spec" => Some(InternalCommand::SbpSpec),
            _ => None,
        }
    }

    pub fn is_supported_version(version: &str) -> bool {
        match version {
            "v1" => true,
            _ => false,
        }
    }
}

pub struct SBPSession {
    // Placeholder for future state management
}

impl SBPSession {
    pub fn new() -> Self {
        Self {}
    }
}
