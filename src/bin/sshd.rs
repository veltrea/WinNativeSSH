use anyhow::Result;
use log::{info, warn};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
use vlt_sshd::audit_codes::{EVT_SERVICE_START, EVT_SERVICE_STOP};
use vlt_sshd::db::Db;
use vlt_sshd::server::WinNativeHandler;

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[cfg(windows)]
const SERVICE_NAME: &str = "WinNativeSSH";
#[derive(Debug, Default, Deserialize)]
struct RuntimeConfig {
    bind_addr: Option<String>,
    db_path: Option<String>,
    host_key_path: Option<String>,
    #[serde(default = "default_max_connections")]
    max_connections: u32,
    #[serde(default = "default_max_auth_attempts")]
    max_auth_attempts: u32,
    #[serde(default = "default_auth_delay_ms")]
    auth_delay_ms: u64,
}

fn default_max_connections() -> u32 { 10 }
fn default_max_auth_attempts() -> u32 { 3 }
fn default_auth_delay_ms() -> u64 { 1000 }

struct WinNativeServer {
    db: Arc<Db>,
    active_connections: Arc<AtomicU32>,
    max_connections: u32,
    max_auth_attempts: u32,
    auth_delay_ms: u64,
}

impl russh::server::Server for WinNativeServer {
    type Handler = WinNativeHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        let addr = peer_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        
        let current_conn = self.active_connections.fetch_add(1, Ordering::SeqCst);
        if current_conn >= self.max_connections {
            warn!("Max connections ({}) reached. Rejecting connection from {}", self.max_connections, addr);
            // We can't easily reject it here in new_client because it returns a Handler.
            // We'll mark the handler as "to be closed" or just let it proceed and handle it in the handler
            // or simply decrement back. Actually russh doesn't provide a clean way to reject here.
            // However, we can return a handler that fails all further steps.
        }

        WinNativeHandler::new(
            self.db.clone(),
            addr,
            self.active_connections.clone(),
            self.max_auth_attempts,
            self.auth_delay_ms,
            current_conn >= self.max_connections
        )
    }
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, my_service_main);

#[cfg(windows)]
fn my_service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(_e) = run_service() {
        // Handle error logging here if needed
    }
}

#[cfg(windows)]
fn run_service() -> Result<()> {
    let (stop_tx, stop_rx) = watch::channel(false);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = stop_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    // Create a runtime and block on the server logic
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        if let Err(e) = run_server(Some(stop_rx)).await {
            log::error!("Server error: {:?}", e);
        }
    });

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

async fn run_server(_stop_rx: Option<watch::Receiver<bool>>) -> Result<()> {
    // env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Logging to file for service debugging.
    //
    // Use ProgramData by default to avoid user-specific paths (and to stay writable for SYSTEM).
    // Override with WNSSH_LOG_PATH if needed.
    let default_log_path = r"C:\ProgramData\WinNativeSSH\logs\sshd.log";
    let log_path = std::env::var("WNSSH_LOG_PATH").unwrap_or_else(|_| default_log_path.to_string());
    if let Some(parent) = Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open(log_path)
    {
        let _ = simplelog::WriteLogger::init(
            simplelog::LevelFilter::Info,
            simplelog::Config::default(),
            file,
        );
    } else {
        // Fallback: try to log to Panic if we can't open file?
        // Or just continue.
    }

    // Enable privileges for CreateProcessAsUserW
    if let Err(e) = vlt_sshd::auth::WindowsAuth::init_process_privileges() {
        log::warn!("Failed to enable process privileges: {:?}", e);
    }

    info!("WinNative-SSH Service starting...");

    // 1. Initialize Database
    let mut exe_dir = std::env::current_exe()?;
    exe_dir.pop();
    let runtime_cfg = load_runtime_config(&exe_dir)?;
    let db_path = resolve_config_path(&exe_dir, runtime_cfg.db_path.as_deref(), "winnative.db");
    let key_path = resolve_config_path(
        &exe_dir,
        runtime_cfg.host_key_path.as_deref(),
        "host_key.pem",
    );
    let bind_addr = runtime_cfg
        .bind_addr
        .unwrap_or_else(|| "0.0.0.0:2222".to_string());

    info!("Database path: {:?}", db_path);
    info!("Host key path: {:?}", key_path);
    info!("Bind address: {}", bind_addr);
    let db = Arc::new(Db::open(db_path)?);
    log_service_event(&db, EVT_SERVICE_START, r#"{"state":"starting"}"#);

    // 2. Load/Generate Host Key
    let key = if key_path.exists() {
        info!("Loading existing host key from {:?}", key_path);
        let key_str = std::fs::read_to_string(&key_path)?;
        russh_keys::decode_secret_key(&key_str, None).map_err(|e| anyhow::anyhow!(e))?
    } else {
        info!("Generating new host key...");
        let key = russh_keys::key::KeyPair::generate_ed25519().ok_or_else(|| anyhow::anyhow!("Failed to generate host key"))?;
        let mut pem_buf = Vec::new();
        russh_keys::encode_pkcs8_pem(&key, &mut pem_buf).map_err(|e| anyhow::anyhow!(e))?;
        std::fs::write(&key_path, pem_buf)?;
        key
    };

    // 3. Configure SSH Server
    const AUTH_BANNER: &str = "WinNativeSSH notice (Windows):\r\n\
If public-key login fails and you suspect the Windows OpenSSH ACL trap:\r\n\
  - Check ACL: GET /acl?path=... (Admin API)\r\n\
  - Repair: vlt-admin fix-permissions <username>\r\n\
Docs: docs/technical/PROBLEM_ANALYSIS_ACL_PERMISSION_TRAP.md\r\n";

    let banner_enabled = std::env::var("WNSSH_AUTH_BANNER")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes"));

    let config = russh::server::Config {
        keys: vec![key],
        auth_banner: if banner_enabled {
            Some(AUTH_BANNER)
        } else {
            None
        },
        ..Default::default()
    };
    let config = Arc::new(config);

    // 4. Start Listening
    info!("Listening on {}", bind_addr);

    let server = WinNativeServer {
        db: db.clone(),
        active_connections: Arc::new(AtomicU32::new(0)),
        max_connections: runtime_cfg.max_connections,
        max_auth_attempts: runtime_cfg.max_auth_attempts,
        auth_delay_ms: runtime_cfg.auth_delay_ms,
    };
    let run_result = {
        #[cfg(windows)]
        {
            if let Some(mut rx) = _stop_rx {
                tokio::select! {
                    r = russh::server::run(config.clone(), bind_addr.clone(), server) => r.map_err(|e| anyhow::anyhow!(e)),
                    changed = rx.changed() => {
                        if matches!(changed, Ok(())) && *rx.borrow() {
                            info!("Service stop requested; shutting down listener");
                        }
                        Ok(())
                    }
                }
            } else {
                russh::server::run(config, bind_addr, server).await.map_err(|e| anyhow::anyhow!(e))
            }
        }
        #[cfg(not(windows))]
        {
            russh::server::run(config, bind_addr, server).await.map_err(|e| anyhow::anyhow!(e))
        }
    };
    let stop_detail = if let Err(ref e) = run_result {
        format!(r#"{{"state":"stopped","result":"error","error":"{}"}}"#, e)
    } else {
        r#"{"state":"stopped","result":"ok"}"#.to_string()
    };
    log_service_event(&db, EVT_SERVICE_STOP, &stop_detail);
    run_result?;
    Ok(())
}

fn log_service_event(db: &Arc<Db>, code: &str, detail_json: &str) {
    if let Err(e) = db.add_audit_event(None, None, "service", code, detail_json) {
        log::warn!("Failed to log service audit event {}: {:?}", code, e);
    }
}

fn load_runtime_config(exe_dir: &Path) -> Result<RuntimeConfig> {
    let path = exe_dir.join("server.json");
    if !path.exists() {
        return Ok(RuntimeConfig::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let cfg: RuntimeConfig = serde_json::from_str(&content)?;
    Ok(cfg)
}

fn resolve_config_path(base_dir: &Path, configured: Option<&str>, default_name: &str) -> PathBuf {
    match configured {
        Some(value) => {
            let p = PathBuf::from(value);
            if p.is_absolute() {
                p
            } else {
                base_dir.join(p)
            }
        }
        None => base_dir.join(default_name),
    }
}

fn main() -> Result<()> {
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        let console_mode = args.contains(&"--console".to_string());
        if !console_mode {
            match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
                Ok(_) => return Ok(()),
                Err(_e) => {
                    // console fall-through
                }
            }
        }
    }

    // Console mode (Linux/Mac or Windows --console)
    tokio::runtime::Runtime::new()?.block_on(run_server(None))
}
