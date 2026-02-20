#[cfg(windows)]
use anyhow::anyhow;
use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
#[allow(unused_imports)]
use log::{error, info};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub volume_path: String, // e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
    pub original_volume: String, // e.g. C:
}

pub struct VssManager;

impl VssManager {
    #[cfg(windows)]
    pub fn list_snapshots() -> Result<Vec<Snapshot>> {
        // [ALGO-03] Replace deprecated 'wmic' with PowerShell Get-CimInstance
        // Use PowerShell for JSON output which is robust and locale-independent
        let command = "Get-CimInstance -Namespace root\\cimv2 -ClassName Win32_ShadowCopy | Select-Object DeviceObject, ID, InstallDate, VolumeName | ConvertTo-Json";
        let output = Command::new("powershell")
            .args(&["-NoProfile", "-Command", command])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("powershell command failed"));
        }

        let stdout = param_string_from_utf8(&output.stdout);
        if stdout.trim().is_empty() {
            return Ok(vec![]);
        }
        Self::parse_powershell_output(&stdout)
    }

    #[cfg(not(windows))]
    pub fn list_snapshots() -> Result<Vec<Snapshot>> {
        Ok(vec![])
    }

    #[allow(dead_code)]
    fn parse_powershell_output(output: &str) -> Result<Vec<Snapshot>> {
        #[derive(Deserialize)]
        struct PsSnapshot {
            #[serde(rename = "DeviceObject")]
            device_object: String,
            #[serde(rename = "ID")]
            id: String,
            #[serde(rename = "InstallDate")]
            install_date: String,
            #[serde(rename = "VolumeName")]
            volume_name: String,
        }

        // PowerShell ConvertTo-Json might return a single object or an array
        let raw_json: serde_json::Value = serde_json::from_str(output)?;
        let ps_snapshots: Vec<PsSnapshot> = if raw_json.is_array() {
            serde_json::from_value(raw_json)?
        } else if raw_json.is_object() {
            vec![serde_json::from_value(raw_json)?]
        } else {
            return Ok(vec![]);
        };

        let mut snapshots = Vec::new();
        for ps in ps_snapshots {
            // Parse date: YYYYMMDDHHMMSS.mmmmm+...
            if ps.install_date.len() < 14 {
                continue;
            }

            let date_str = &ps.install_date[..14];
            if let Ok(nd) = NaiveDateTime::parse_from_str(date_str, "%Y%m%d%H%M%S") {
                let created_at = DateTime::<Utc>::from_naive_utc_and_offset(nd, Utc);
                snapshots.push(Snapshot {
                    id: ps.id,
                    created_at,
                    volume_path: ps.device_object,
                    original_volume: ps.volume_name,
                });
            }
        }
        Ok(snapshots)
    }
}

#[cfg(windows)]
fn param_string_from_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}
