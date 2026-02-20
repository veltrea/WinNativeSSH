use crate::audit_codes::*;
use crate::auth::{UserToken, WindowsAuth};
use crate::client_info::ClientInfo;
use crate::core_syslog::VltLogger;
use crate::db::Db;
use crate::protocol::WorkerToService;
use crate::worker_broker::{ControlMessage, WorkerBroker};
use anyhow::Result;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use log::{info, warn, error};
use russh::server::Msg;
use russh::{server, server::Handler, server::Session, Channel, ChannelId};

use russh_keys::PublicKeyBase64;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;


use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct KeyConstraints {
    source_ips: Option<Vec<String>>,
}

pub struct WinNativeHandler {
    pub client_info: Option<ClientInfo>,
    pub db: Arc<Db>,
    pub logger: VltLogger,
    pub brokers: HashMap<ChannelId, Arc<WorkerBroker>>,
    pub pending_channels: HashMap<ChannelId, Channel<Msg>>,
    pub auth_token: Arc<Mutex<Option<UserToken>>>,
    pub client_user: Arc<Mutex<Option<String>>>,
    pub client_sid: Arc<Mutex<Option<String>>>,
    pub client_addr: SocketAddr,
    pub active_connections: Arc<AtomicU32>,
    pub auth_attempts: u32,
    pub max_auth_attempts: u32,
    pub auth_delay_ms: u64,
    pub exceeds_limit: bool,
    pub last_activity: Arc<Mutex<Instant>>,
}

impl WinNativeHandler {
    pub fn new(
        db: Arc<Db>,
        client_addr: SocketAddr,
        active_connections: Arc<AtomicU32>,
        max_auth_attempts: u32,
        auth_delay_ms: u64,
        exceeds_limit: bool,
    ) -> Self {
        let server_ip =
            std::env::var("VLT_SYSLOG_SERVER").unwrap_or_else(|_| "127.0.0.1".to_string());
        WinNativeHandler {
            client_info: None,
            db,
            logger: VltLogger::new(&server_ip, "vlt-sshd"),
            brokers: HashMap::new(),
            pending_channels: HashMap::new(),
            auth_token: Arc::new(Mutex::new(None)),
            client_user: Arc::new(Mutex::new(None)),
            client_sid: Arc::new(Mutex::new(None)),
            client_addr,
            active_connections,
            auth_attempts: 0,
            max_auth_attempts,
            auth_delay_ms,
            exceeds_limit,
            last_activity: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

impl Drop for WinNativeHandler {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

impl WinNativeHandler {

    fn check_key(&self, user: &str, offered_key: &russh_keys::key::PublicKey) -> Result<bool> {
        let db_user = self.db.get_user_by_name(user)?;
        if let Some(u) = db_user {
            if !u.enabled {
                warn!("User {} is disabled in database", user);
                return Ok(false);
            }
            let keys = self.db.get_keys_for_user(&u.sid)?;
            let offered_string = offered_key.public_key_base64();
            // Basic check if the key is in our DB.
            // We assume DB stores full OpenSSH keys or just the base64.
            // to_string() returns 'ssh-rsa AAA...'
            for k in keys {
                if k.enabled {
                    // 1. Check expiration
                    if let Some(ref expires_str) = k.expires_at {
                        if let Ok(expires_at) = expires_str.parse::<DateTime<Utc>>() {
                            if Utc::now() > expires_at {
                                warn!("Public key for {} has expired at {}", user, expires_str);
                                continue;
                            }
                        }
                    }

                    // 2. Check source IP constraints
                    if let Some(ref constraints_json) = k.constraints_json {
                        if let Ok(constraints) = serde_json::from_str::<KeyConstraints>(constraints_json) {
                            if let Some(ref allowed_ips) = constraints.source_ips {
                                let client_ip = self.client_addr.ip().to_string();
                                if !allowed_ips.contains(&client_ip) {
                                    warn!("Public key for {} is not allowed from IP {}", user, client_ip);
                                    continue;
                                }
                            }
                        }
                    }

                    let parts: Vec<&str> = k.pubkey.split_whitespace().collect();
                    let key_to_compare = if parts.len() >= 2 { parts[1] } else { &k.pubkey };
                    if offered_string == key_to_compare {
                        info!("Public key match successful for {}", user);
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    async fn launch_worker(
        self,
        channel_id: ChannelId,
        session: Session,
        subsystem: Option<String>,
        command: Option<String>,
    ) -> Result<(Self, Session), anyhow::Error> {
        match self.launch_worker_internal(channel_id, session, subsystem, command).await {
            Ok(res) => Ok(res),
            Err(e) => {
                log::error!("launch_worker failed: {:?}", e);
                Err(e)
            }
        }
    }

    async fn launch_worker_internal(
        mut self,
        channel_id: ChannelId,
        session: Session,
        subsystem: Option<String>,
        command: Option<String>,
    ) -> Result<(Self, Session), anyhow::Error> {
        let auth_token_ref = self.auth_token.clone();
        let mut user_token_opt = auth_token_ref.lock().await;
        // Proceed even if no token is available (fallback spawn will be used)

        let remote_addr_str = self.client_addr.to_string();
        self.logger
            .auth_info(&format!("New SSH session from {}", remote_addr_str))
            .await;

        let channel = self
            .pending_channels
            .remove(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("Channel not found in pending_channels"))?;

        let sid = {
            let sid_lock = self.client_sid.lock().await;
            sid_lock.clone().unwrap_or_else(|| "unknown".to_string())
        };

        let relay_session_id = uuid::Uuid::new_v4().to_string();
        let db = self.db.clone();
        let src_ip = self.client_addr.ip().to_string();
        let src_port = self.client_addr.port() as i64;

        let mut broker = WorkerBroker::new(channel, relay_session_id.clone());

        #[cfg(windows)]
        let mut attached = false;
        #[cfg(windows)]
        {
            // Attempt to attach to existing session if possible (Placeholder for stateful session ID)
            if let Ok(true) = broker.try_attach_existing().await {
                info!("Re-attached to existing worker for session {}", relay_session_id);
                attached = true;
            }
        }

        let mut worker_pid = None;
        let pipe_name_str = broker.pipe_name();

        #[cfg(windows)]
        if !attached {
            let server = WorkerBroker::create_pipe_with_security(&pipe_name_str, true)?;
            let mut exe_path = std::env::current_exe()?;
            exe_path.pop();
            exe_path.push("vlt-worker.exe");
            let cmd = format!("\"{}\" --worker --pipe {}", exe_path.display(), pipe_name_str);

            if let Err(e) = crate::auth::WindowsAuth::init_process_privileges() {
                log::error!("Failed to init process privileges: {:?}", e);
            }

            let opts = crate::auth::SpawnOptions {
                command_line: cmd,
                ..Default::default()
            };

            let spawn_res = if let Some(token) = user_token_opt.as_mut() {
                match crate::auth::WindowsAuth::spawn_as_user(token, opts) {
                    Ok(pid) => Ok(pid),
                    Err(e) => Err(anyhow::anyhow!("spawn_as_user failed: {:?}", e)),
                }
            } else {
                Err(anyhow::anyhow!("No Windows user token available"))
            };

            let pid = match spawn_res {
                Ok(pid) => {
                    log::info!("Spawned worker process as user: {}", pid);
                    pid
                }
                Err(e) => {
                    log::warn!("{}, falling back to current process context", e);
                    let mut cmd = std::process::Command::new("vlt-worker.exe");
                    cmd.arg("--worker").arg("--pipe").arg(&pipe_name_str);

                    // Use same directory as server
                    if let Ok(mut p) = std::env::current_exe() {
                        p.pop();
                        cmd.current_dir(p);
                    }

                    match cmd.spawn() {
                        Ok(child) => {
                            log::info!("Spawned worker process in fallback mode: {}", child.id());
                            child.id()
                        }
                        Err(e) => {
                            let err_msg = format!("Fallback spawn failed: {:?}", e);
                            log::error!("{}", err_msg);
                            return Err(anyhow::anyhow!(err_msg));
                        }
                    }
                }
            };
            worker_pid = Some(pid);
            
            // Important: wait for worker to connect to the pipe we just created
            broker.wait_for_worker(server).await?;
        }

        if let Err(e) = db.start_session(
            &relay_session_id,
            Some(&sid),
            Some(&src_ip),
            Some(src_port),
            worker_pid,
            Some(&pipe_name_str),
        ) {
            error!("Failed to start/update session record: {:?}", e);
        }

        let broker = Arc::new(broker);
        self.brokers.insert(channel_id, broker.clone());

        // --- Output Forwarding Loop ---
        // Spawn a background task to read from the broker and forward to the SSH channel.
        let broker_clone = broker.clone();
        let channel_handle = channel_id;
        let session_handle = session.handle();
        let last_activity_clone = self.last_activity.clone();

        tokio::spawn(async move {
            let broker = broker_clone; // Arc<WorkerBroker>
            let last_activity = last_activity_clone;
            loop {
                // Now receive_message takes &self key handling the internal mutex
                match broker.receive_message().await {
                    Ok(Some(msg)) => {
                        // Update last activity on output from worker
                        {
                            let mut last = last_activity.lock().await;
                            *last = Instant::now();
                        }
                        match msg {
                            WorkerToService::OutputData { data } => {
                                // Base64 decode
                                match general_purpose::STANDARD.decode(&data) {
                                    Ok(decoded) => {
                                        // Forward to SSH channel
                                        let _ = session_handle
                                            .data(channel_handle, decoded.into())
                                            .await;
                                    }
                                    Err(e) => {
                                        log::error!("Failed to decode base64 output: {:?}", e);
                                    }
                                }
                            }
                            WorkerToService::SessionEnded { result } => {
                                info!("Worker session ended with result: {}", result);
                                // Parse result to exit code if possible, or default to 0
                                let exit_status = if result == "Ok" { 0 } else { 1 };
                                let _ = session_handle
                                    .exit_status_request(channel_handle, exit_status)
                                    .await;
                                let _ = session_handle.close(channel_handle).await;
                                break;
                            }
                            _ => {
                                // Handle other messages or ignore
                            }
                        }
                    }
                    Ok(None) => {
                        // Pipe closed or EOF
                        log::info!("Worker pipe received EOF. Closing SSH channel.");
                        let _ = session_handle.exit_status_request(channel_handle, 0).await; // Assume success or unknown
                        let _ = session_handle.close(channel_handle).await;
                        break;
                    }
                    Err(e) => {
                        log::error!("Error receiving from worker: {:?}", e);
                        let _ = session_handle.exit_status_request(channel_handle, 1).await;
                        let _ = session_handle.close(channel_handle).await;
                        break;
                    }
                }
            }
        });

        // --- Send Initial Command/Policy ---
        let policy = self.db.get_effective_policy(&sid).unwrap_or(crate::protocol::Policy {
            allow_exec: true,
            allow_port_forwarding: true,
            terminal_encoding: "utf-8".to_string(),
            idle_timeout_seconds: 0,
        });

        // --- Idle Timeout Monitor ---
        if policy.idle_timeout_seconds > 0 {
            let last_activity = self.last_activity.clone();
            let session_handle_monitor = session.handle();
            let channel_handle_monitor = channel_id;
            let timeout_secs = policy.idle_timeout_seconds as u64;
            let session_id_str = relay_session_id.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    let last = {
                        let lock = last_activity.lock().await;
                        *lock
                    };
                    if last.elapsed().as_secs() >= timeout_secs {
                        log::info!("Session {} idle timeout reached ({}s). Closing.", session_id_str, timeout_secs);
                        let _ = session_handle_monitor.data(channel_handle_monitor, russh::CryptoVec::from_slice("\r\n[Session idle timeout reached. Closing connection.]\r\n".as_bytes())).await;
                        let _ = session_handle_monitor.close(channel_handle_monitor).await;
                        break;
                    }
                }
            });
        }

        let msg = crate::protocol::ServiceToWorker::ApplyPolicy {
            policy: policy.clone(),
            _subsystem: subsystem,
            command: command,
        };

        if let Err(e) = broker.send_message(msg).await {
            let err_msg = format!("Failed to send APPLY_POLICY to worker: {:?}", e);
            log::error!("{}", err_msg);
            return Err(anyhow::anyhow!(err_msg));
        }

        Ok((self, session))
    }
}

#[async_trait]
impl Handler for WinNativeHandler {
    type Error = anyhow::Error;

    // finished_auth removed (not in trait)

    async fn auth_publickey(
        mut self,
        user: &str,
        key: &russh_keys::key::PublicKey,
    ) -> Result<(Self, server::Auth), Self::Error> {
        if self.exceeds_limit {
            return Ok((self, server::Auth::Reject { proceed_with_methods: None }));
        }

        self.auth_attempts += 1;
        if self.auth_attempts > self.max_auth_attempts {
            warn!("Too many authentication attempts for user {} from {}", user, self.client_addr);
            return Ok((self, server::Auth::Reject { proceed_with_methods: None }));
        }

        info!("Authenticating user {} with public key (attempt {})", user, self.auth_attempts);
        let db = self.db.clone();

        match self.check_key(user, key) {
            Ok(true) => {
                let db_user = db.get_user_by_name(user)?;
                if let Some(u) = db_user {
                    if let Some(enc_pass) = u.password_enc {
                        if let Ok(pass_bytes) = crate::dpapi::unprotect(&enc_pass) {
                            if let Ok(pass_str) = String::from_utf8(pass_bytes) {
                                if let Some(token) = WindowsAuth::authenticate(user, &pass_str) {
                                    {
                                        let mut token_lock = self.auth_token.lock().await;
                                        *token_lock = Some(token);
                                    }
                                    {
                                        let mut user_lock = self.client_user.lock().await;
                                        *user_lock = Some(user.to_string());
                                    }
                                    {
                                        let mut sid_lock = self.client_sid.lock().await;
                                        *sid_lock = Some(u.sid.clone());
                                    }
                                    info!(
                                        "Public key auth + DPAPI password logon successful for {}",
                                        user
                                    );
                                    self.logger.auth_info(&format!(
                                        "User {} authenticated successfully via public key",
                                        user
                                    )).await;
                                    return Ok((self, server::Auth::Accept));
                                } else {
                                    warn!("Public key matched but Windows logon failed for {}", user);
                                    return Ok((self, server::Auth::Reject { proceed_with_methods: None }));
                                }
                            }
                        }
                    }
                }


                warn!(
                    "Public key accepted for {}, but no Windows token obtained. Rejecting session.",
                    user
                );
                self.logger.auth_info(&format!(
                    "User {} authenticated via public key, but no Windows token obtained. Rejecting.",
                    user
                )).await;
                Ok((self, server::Auth::Reject { proceed_with_methods: None }))
            }
            _ => {
                let detail = format!(
                    r#"{{"result":"fail","method":"publickey","user":"{}","client_addr":"{}"}}"#,
                    user, self.client_addr
                );
                if let Err(e) = db.add_audit_event(None, Some(user), "auth", EVT_AUTH_FAIL, &detail) {
                    error!("Failed to write audit event: {:?}", e);
                }

                // ACL Diagnosis on failure (Windows only)
                #[cfg(windows)]
                {
                    use crate::acl_diagnose;
                    use crate::auth::get_user_info_windows;
                    use std::path::Path;

                    match get_user_info_windows(user) {
                        Ok(info) => {
                            let ssh_dir = Path::new(&info.profile_path).join(".ssh");
                            let auth_keys = ssh_dir.join("authorized_keys");

                            info!("Running ACL diagnosis for failed auth of user {}", user);
                            if ssh_dir.exists() {
                                if let Ok(diag) =
                                    acl_diagnose::diagnose_path(&ssh_dir, Some(&info.sid))
                                {
                                    if !diag.is_valid {
                                        warn!(
                                            "ACL Issue detected in .ssh directory: {} ({})",
                                            diag.failure_reason.unwrap_or_default(),
                                            diag.details.join(", ")
                                        );
                                    }
                                }
                            }
                            if auth_keys.exists() {
                                if let Ok(diag) =
                                    acl_diagnose::diagnose_path(&auth_keys, Some(&info.sid))
                                {
                                    if !diag.is_valid {
                                        warn!(
                                            "ACL Issue detected in authorized_keys: {} ({})",
                                            diag.failure_reason.unwrap_or_default(),
                                            diag.details.join(", ")
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Could not run ACL diagnosis for user {}: {:?}", user, e);
                        }
                    }
                }

                if self.auth_delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(self.auth_delay_ms)).await;
                }

                Ok((
                    self,
                    server::Auth::Reject {
                        proceed_with_methods: None,
                    },
                ))
            }
        }
    }

    async fn auth_password(
        mut self,
        user: &str,
        pass: &str,
    ) -> Result<(Self, server::Auth), Self::Error> {
        if self.exceeds_limit {
            return Ok((self, server::Auth::Reject { proceed_with_methods: None }));
        }

        self.auth_attempts += 1;
        if self.auth_attempts > self.max_auth_attempts {
            warn!("Too many authentication attempts for user {} from {}", user, self.client_addr);
            return Ok((self, server::Auth::Reject { proceed_with_methods: None }));
        }

        info!("Authenticating user {} with password (attempt {})", user, self.auth_attempts);

        if let Some(token) = WindowsAuth::authenticate(user, pass) {
            {
                let mut token_lock = self.auth_token.lock().await;
                *token_lock = Some(token);
            }
            {
                let mut user_lock = self.client_user.lock().await;
                *user_lock = Some(user.to_string());
            }

            let db_user = self.db.get_user_by_name(user)?;
            if let Some(u) = db_user {
                let mut sid_lock = self.client_sid.lock().await;
                *sid_lock = Some(u.sid.clone());

                // Store password encrypted via DPAPI for future key-only logins
                if let Ok(enc) = crate::dpapi::protect(pass.as_bytes()) {
                    let _ = self.db.set_user_password_enc(&u.sid, &enc);
                }
            } else {
                // Should we create user here if they authenticated with Windows?
                // For now, only if we can't find them in DB but Windows liked them.
                // But we don't have a SID easily from WindowsAuth::authenticate token.
                // Actually, if they authenticated, they might be in DB. If not, we don't have SID to create.
            }
            self.logger.auth_info(&format!(
                "User {} authenticated successfully via password",
                user
            )).await;
            Ok((self, server::Auth::Accept))
        } else {
            let detail = format!(
                r#"{{"result":"fail","method":"password","user":"{}","client_addr":"{}"}}"#,
                user, self.client_addr
            );
            if let Err(e) = self
                .db
                .add_audit_event(None, Some(user), "auth", EVT_AUTH_FAIL, &detail) {
                error!("Failed to write audit event: {:?}", e);
            }
            
            if self.auth_delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.auth_delay_ms)).await;
            }

            Ok((
                self,
                server::Auth::Reject {
                    proceed_with_methods: None,
                },
            ))
        }
    }

    async fn channel_open_session(
        mut self,
        channel: Channel<Msg>,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        if self.exceeds_limit {
            return Ok((self, false, session));
        }

        info!(
            "Channel open session requested for channel {:?}",
            channel.id()
        );
        self.pending_channels.insert(channel.id(), channel);
        Ok((self, true, session))
    }

    async fn shell_request(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        info!("Shell requested for channel {:?}", channel);
        self.launch_worker(channel, session, None, None).await
    }

    async fn subsystem_request(
        self,
        channel: ChannelId,
        name: &str,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        info!("Subsystem '{}' requested for channel {:?}", name, channel);
        self.launch_worker(channel, session, Some(name.to_string()), None)
            .await
    }

    async fn exec_request(
        self,
        channel: ChannelId,
        command: &[u8],
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        let command_str = String::from_utf8_lossy(command).to_string();
        info!("Exec '{}' requested for channel {:?}", command_str, channel);
        self.launch_worker(channel, session, None, Some(command_str))
            .await
    }

    async fn data(
        self,
        channel: ChannelId,
        data: &[u8],
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        // Update last activity on input from client
        {
            let mut last = self.last_activity.lock().await;
            *last = Instant::now();
        }
        if let Some(broker) = self.brokers.get(&channel) {
            broker
                .send_to_worker(ControlMessage::Data(data.to_vec()))
                .await?;
        }
        Ok((self, session))
    }

    // tcpip_forward removed (using default or will fix later if missing)

    async fn channel_open_direct_tcpip(
        self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _originator_address: &str,
        _originator_port: u32,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        info!(
            "Direct TCPIP request to {}:{} on channel {:?}",
            host,
            port,
            channel.id()
        );

        let sid = {
            let sid_lock = self.client_sid.lock().await;
            sid_lock.clone().unwrap_or_else(|| "unknown".to_string())
        };

        let policy = self.db.get_effective_policy(&sid)?;
        let allowed = policy.allow_port_forwarding;

        if allowed {
            info!("Port forwarding to {}:{} allowed by policy", host, port);
        } else {
            warn!("Port forwarding to {}:{} denied by policy", host, port);
        }

        Ok((self, allowed, session))
    }

    async fn channel_eof(
        self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        if let Some(broker) = self.brokers.get(&channel) {
            let _ = broker.send_to_worker(ControlMessage::Eof).await;
        }
        Ok((self, session))
    }

    async fn channel_close(
        mut self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        info!("Channel {:?} closed", channel);
        if let Some(broker) = self.brokers.remove(&channel) {
            let relay_session_id = broker.session_id().to_string();
            let db = self.db.clone();
            let sid = {
                let sid_opt = self.client_sid.lock().await;
                sid_opt.clone()
            };

            tokio::spawn(async move {
                let detail = format!(r#"{{"session_id":"{}"}}"#, relay_session_id);
                if let Err(e) = db.add_audit_event(
                    Some(&relay_session_id),
                    sid.as_deref(),
                    "session",
                    EVT_SESSION_END,
                    &detail,
                ) {
                    error!("Failed to write audit event ({}): {:?}", EVT_SESSION_END, e);
                }
                if let Err(e) = db.end_session(&relay_session_id, "relay_ended") {
                    error!("Failed to end session record: {:?}", e);
                }
            });
        }

        Ok((self, session))
    }
}
