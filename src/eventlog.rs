#[cfg(windows)]
pub fn write_event(category: &str, code: &str, detail_json: &str) {
    use crate::audit_codes;
    use std::process::Command;

    let id = code.parse::<u32>().unwrap_or(1000).clamp(1, 1000);
    let event_type = if audit_codes::is_warning(code) {
        "WARNING"
    } else {
        "INFORMATION"
    };
    let mut message = format!("[{}:{}] {}", category, code, detail_json);
    if message.len() > 30000 {
        message.truncate(30000);
    }

    let result = Command::new("eventcreate")
        .args([
            "/L",
            "APPLICATION",
            "/SO",
            "WinNativeSSH",
            "/T",
            event_type,
            "/ID",
            &id.to_string(),
            "/D",
            &message,
        ])
        .output();

    if let Err(e) = result {
        log::warn!("EventLog write failed: {:?}", e);
    }
}

#[cfg(not(windows))]
pub fn write_event(_category: &str, _code: &str, _detail_json: &str) {}
