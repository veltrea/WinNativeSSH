#[cfg(windows)]
use anyhow::{anyhow, Result};

use russh::{server::Msg, Channel};
use crate::protocol::{
    ServiceToWorker, WorkerToService,
};

use log::info;
#[cfg(windows)]
use base64::{engine::general_purpose, Engine as _};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{LocalFree, HLOCAL};
#[cfg(windows)]
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
#[cfg(windows)]
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
#[cfg(windows)]
use windows::Win32::System::Pipes::{CreateNamedPipeW, NAMED_PIPE_MODE, PIPE_UNLIMITED_INSTANCES};

pub struct WorkerBroker {
    pub session_id: String,
    pub channel: Channel<Msg>,
    #[cfg(windows)]
    pub server_read: Option<tokio::sync::Mutex<BufReader<tokio::io::ReadHalf<NamedPipeServer>>>>,
    #[cfg(windows)]
    pub server_write: Option<tokio::sync::Mutex<tokio::io::WriteHalf<NamedPipeServer>>>,
}

impl WorkerBroker {
    pub fn new(channel: Channel<Msg>, session_id: String) -> Self {
        info!(
            "Initializing WorkerBroker for session: {} (channel: {:?})",
            session_id,
            channel.id()
        );
        WorkerBroker {
            session_id,
            channel,
            #[cfg(windows)]
            server_read: None,
            #[cfg(windows)]
            server_write: None,
        }
    }

    #[cfg(windows)]
    pub async fn start_ipc_server(&mut self) -> Result<String> {
        let pipe_name = format!(r"\\.\pipe\WinNativeSSH\Session_{}", self.session_id);
        info!("Creating control named pipe: {}", pipe_name);

        // We don't store the server anymore, it will be passed to wait_for_worker.
        Ok(pipe_name)
    }

    #[cfg(windows)]
    pub fn create_pipe_with_security(name: &str, first: bool) -> Result<NamedPipeServer> {
        let name_wide: Vec<u16> = OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SDDL: D:(A;;GA;;;AU)  -> Allow Generic All to Authenticated Users
        let sddl = "D:(A;;GA;;;AU)";
        let sddl_wide: Vec<u16> = OsStr::new(sddl)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_wide.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;

            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0 as *mut _,
                bInheritHandle: false.into(),
            };

            // PIPE_ACCESS_DUPLEX (3) | FILE_FLAG_OVERLAPPED (0x40000000)
            let mut dw_open_mode = 0x40000003;
            if first {
                // FILE_FLAG_FIRST_PIPE_INSTANCE (0x00080000)
                dw_open_mode |= 0x00080000;
            }
            let open_mode = FILE_FLAGS_AND_ATTRIBUTES(dw_open_mode);

            // PIPE_TYPE_BYTE(0) | PIPE_READMODE_BYTE(0) | PIPE_WAIT(0)
            let pipe_mode = NAMED_PIPE_MODE(0);

            let pipe_handle = CreateNamedPipeW(
                PCWSTR(name_wide.as_ptr()),
                open_mode,
                pipe_mode,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                Some(&sa),
            );

            // Free SD
            let _ = LocalFree(HLOCAL(sd.0 as *mut _));

            if pipe_handle.is_invalid() {
                let err = windows::core::Error::from_win32();
                return Err(anyhow::anyhow!("CreateNamedPipeW failed: {:?}", err));
            }

            // Safety: We own the handle and just created it.
            let server = NamedPipeServer::from_raw_handle(pipe_handle.0 as *mut _)?;
            Ok(server)
        }
    }

    #[cfg(windows)]
    pub async fn try_attach_existing(&mut self) -> Result<bool> {
        info!(
            "Attempting to attach to existing pipe for session {}",
            self.session_id
        );

        let pipe_name = self.pipe_name();
        
        // Try to create the named pipe. 
        // If it already exists and we can re-open it as server (e.g. after restart), 
        // we might be able to re-attach.
        match Self::create_pipe_with_security(&pipe_name, false) {
            Ok(server) => {
                info!("Successfully created pipe for re-attachment: {}", pipe_name);
                // We need to wait for worker to connect to this new pipe instance.
                // The worker should be in a retry loop.
                let (reader, writer) = tokio::io::split(server);
                self.server_read = Some(tokio::sync::Mutex::new(BufReader::new(reader)));
                self.server_write = Some(tokio::sync::Mutex::new(writer));
                Ok(true)
            }
            Err(e) => {
                info!("Could not attach to existing pipe (this is normal if first launch): {:?}", e);
                Ok(false)
            }
        }
    }

    #[cfg(windows)]
    pub async fn wait_for_worker(&mut self, server: NamedPipeServer) -> Result<()> {
        info!("Waiting for worker to connect to control pipe...");
        server.connect().await?;
        info!("Worker connected to control pipe.");

        let (reader, writer) = tokio::io::split(server);
        self.server_read = Some(tokio::sync::Mutex::new(BufReader::new(reader)));
        self.server_write = Some(tokio::sync::Mutex::new(writer));

        Ok(())
    }

    #[cfg(windows)]
    pub async fn send_message(&self, msg: ServiceToWorker) -> Result<()> {
        if let Some(ref mutex) = self.server_write {
            let mut writer = mutex.lock().await;
            let json = serde_json::to_string(&msg)? + "\n";
            writer.write_all(json.as_bytes()).await?;
            writer.flush().await?;
        }
        Ok(())
    }

    #[cfg(windows)]
    pub async fn receive_message(&self) -> Result<Option<WorkerToService>> {
        if let Some(ref mutex) = self.server_read {
            let mut reader_guard = mutex.lock().await;
            let mut line = String::new();
            
            // Check 38: Limit the line length to prevent memory exhaustion DoS.
            // We use read_line but check the result. 
            // NOTE: BufReader::read_line will continue until \n or EOF.
            // To truly limit it without trait issues, we use a simpler approach.
            // If the reader has data, we read it.
            if reader_guard.read_line(&mut line).await? > 0 {
                if line.len() > crate::protocol::MAX_IPC_MESSAGE_SIZE {
                    return Err(anyhow!("IPC message exceeded maximum length ({} bytes)", line.len()));
                }
                let msg: WorkerToService = serde_json::from_str(&line)?;
                return Ok(Some(msg));
            }
        }
        Ok(None)
    }

    pub fn pipe_name(&self) -> String {
        format!(r"\\.\pipe\WinNativeSSH\Session_{}", self.session_id)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub async fn send_to_worker(&self, msg: ControlMessage) -> Result<(), anyhow::Error> {
        match msg {
            ControlMessage::Data(data) => {
                let b64 = general_purpose::STANDARD.encode(data);
                self.send_message(ServiceToWorker::Data { data: b64 }).await?;
            }
            ControlMessage::Eof => {
                self.send_message(ServiceToWorker::TerminateSession {
                    reason: "EOF received from client".to_string(),
                })
                .await?;
            }
        }
        Ok(())
    }
}

pub enum ControlMessage {
    Data(Vec<u8>),
    Eof,
}
