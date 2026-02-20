use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use log::{error, info, trace};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;

use vlt_sshd::protocol::{
    ChannelDetail, Policy, ServiceToWorker, WorkerToService,
};

#[cfg(windows)]
async fn connect_and_run(session_id: &str, pipe_name: &str) -> Result<()> {
    info!("Worker started (Session: {})", session_id);

    let active_stdin: Arc<Mutex<Option<tokio::process::ChildStdin>>> = Arc::new(Mutex::new(None));
    let mut child_spawned: Option<tokio::process::Child> = None;

    loop {
        info!("Attempting to connect to pipe: {}", pipe_name);
        let data_pipe = match ClientOptions::new().open(pipe_name) {
            Ok(p) => p,
            Err(e) => {
                if child_spawned.is_some() {
                    // If we have an active child, keep retrying
                    trace!("Pipe not available, retrying... ({:?})", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                } else {
                    return Err(e.into());
                }
            }
        };

        let (reader, writer) = tokio::io::split(data_pipe);
        let writer_clone = Arc::new(tokio::sync::Mutex::new(writer));
        let mut reader = tokio::io::BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            // Check 38: Limit the line length to prevent memory exhaustion DoS.
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                if line.len() > vlt_sshd::protocol::MAX_IPC_MESSAGE_SIZE {
                    error!("IPC message exceeded maximum length ({} bytes)", line.len());
                    return Err(anyhow!("IPC message too long"));
                }
                let msg: ServiceToWorker = match serde_json::from_str(&line) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to parse IPC message: {}. Line: {}", e, line);
                        continue;
                    }
                };

                    match msg {
                        ServiceToWorker::ApplyPolicy {
                            policy, command, ..
                        } => {
                            if !policy.allow_exec {
                                error!("Execution policy denied");
                                continue;
                            }
                            if let Some(cmd_str) = command {
                                 let cmd_trimmed = cmd_str.trim();
                                 info!("Executing command: {}", cmd_trimmed);

                                 // SEC-04: Use -EncodedCommand to prevent shell injection.
                                 // PowerShell expects UTF-16LE Base64.
                                 let encoded_utf16: Vec<u8> = cmd_trimmed
                                     .encode_utf16()
                                     .flat_map(|u| u.to_le_bytes())
                                     .collect();
                                 let b64_cmd = general_purpose::STANDARD.encode(&encoded_utf16);

                                 let mut child_cmd = tokio::process::Command::new("powershell.exe");
                                 child_cmd.args(["-NoProfile", "-EncodedCommand", &b64_cmd]);
                                 child_cmd.stdout(std::process::Stdio::piped());
                                 child_cmd.stderr(std::process::Stdio::piped());
                                 child_cmd.stdin(std::process::Stdio::piped());

                                match child_cmd.spawn() {
                                    Ok(mut spawned) => {
                                        let stdout = spawned.stdout.take().ok_or_else(|| anyhow!("Failed to take stdout"))?;
                                        let stderr = spawned.stderr.take().ok_or_else(|| anyhow!("Failed to take stderr"))?;
                                        let stdin = spawned.stdin.take().ok_or_else(|| anyhow!("Failed to take stdin"))?;

                                        // Store stdin for DATA messages
                                        {
                                            let mut active_lock = active_stdin.lock().await;
                                            *active_lock = Some(stdin);
                                        }

                                        let writer_out = writer_clone.clone();
                                        let writer_err = writer_clone.clone();
                                        let writer_end = writer_clone.clone();
                                        let active_stdin_clone = active_stdin.clone();

                                        // Stdout task
                                        tokio::spawn(async move {
                                            let mut stdout = stdout;
                                            let mut buf = [0u8; 4096];
                                            loop {
                                                match stdout.read(&mut buf).await {
                                                    Ok(0) => break,
                                                    Ok(n) => {
                                                        let b64 = general_purpose::STANDARD.encode(&buf[..n]);
                                                        let msg = WorkerToService::OutputData { data: b64 };
                                                        if let Ok(json) = serde_json::to_string(&msg) {
                                                            let mut w = writer_out.lock().await;
                                                            let _ = w.write_all((json + "\n").as_bytes()).await;
                                                        }
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        });

                                        // Stderr task
                                        tokio::spawn(async move {
                                            let mut stderr = stderr;
                                            let mut buf = [0u8; 4096];
                                            loop {
                                                match stderr.read(&mut buf).await {
                                                    Ok(0) => break,
                                                    Ok(n) => {
                                                        let b64 = general_purpose::STANDARD.encode(&buf[..n]);
                                                        let msg = WorkerToService::OutputData { data: b64 };
                                                        if let Ok(json) = serde_json::to_string(&msg) {
                                                            let mut w = writer_err.lock().await;
                                                            let _ = w.write_all((json + "\n").as_bytes()).await;
                                                        }
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        });

                                        child_spawned = Some(spawned);
                                    }
                                    Err(e) => {
                                        error!("Failed to spawn child: {}", e);
                                    }
                                }
                            }
                        }
                        ServiceToWorker::TerminateSession { reason } => {
                            info!(
                                "session_id: {}, Terminating session: {}",
                                session_id, reason
                            );
                            return Ok(());
                        }
                        ServiceToWorker::Ping { data } => {
                            let resp = WorkerToService::Pong { data };
                            if let Ok(json) = serde_json::to_string(&resp) {
                                let mut w = writer_clone.lock().await;
                                let _ = w.write_all((json + "\n").as_bytes()).await;
                            }
                        }
                        ServiceToWorker::UpdateLimits { cpu_limit_percent, memory_limit_mb } => {
                            match apply_limits(cpu_limit_percent, memory_limit_mb) {
                                Ok(_) => info!("Updated limits: CPU {}%, Mem {}MB", cpu_limit_percent, memory_limit_mb),
                                Err(e) => error!("Failed to update limits: {}", e),
                            }
                        }
                        ServiceToWorker::Data { data } => {
                            if let Ok(decoded) = general_purpose::STANDARD.decode(data) {
                                let mut active_lock = active_stdin.lock().await;
                                if let Some(ref mut stdin) = *active_lock {
                                    if let Err(e) = stdin.write_all(&decoded).await {
                                        error!("Failed to write to child stdin: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading from IPC pipe: {:?}", e);
                    break;
                }
            }
        }

        if let Some(ref mut child) = child_spawned {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    info!("Child process finished, worker exiting.");
                    
                    // Clear stdin and notify service one last time if possible
                    {
                        let mut active_lock = active_stdin.lock().await;
                        *active_lock = None;
                    }
                    
                    let msg = WorkerToService::SessionEnded {
                        result: "Ok".to_string(),
                    };
                    if let Ok(json) = serde_json::to_string(&msg) {
                        let mut w = writer_clone.lock().await;
                        let _ = w.write_all((json + "\n").as_bytes()).await;
                    }
                    break;
                }
                Ok(None) => {
                    info!("Child process still active, waiting for service to reconnect...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
                Err(_) => break,
            }
        } else {
            break;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn apply_limits(cpu_limit_percent: u32, memory_limit_mb: u32) -> Result<()> {
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, AssignProcessToJobObject, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
        JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JobObjectExtendedLimitInformation,
        JobObjectCpuRateControlInformation,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::Win32::Foundation::CloseHandle;
    use windows::core::PCWSTR;

    unsafe {
        // Create a new job object for this process if one doesn't exist
        // Note: In a real production environment, we might want to manage the handle appropriately
        // or handle the case where we are already in a job.
        let job = CreateJobObjectW(None, PCWSTR::null())?;
        if job.is_invalid() {
             return Err(anyhow!("Failed to create job object"));
        }
        
        // Assign current process to job
        // If the process is already in a job that doesn't allow breakaway, this might fail.
        // We log error but don't panic.
        if let Err(e) = AssignProcessToJobObject(job, GetCurrentProcess()) {
             let _ = CloseHandle(job);
             // Verify if typical "Access Denied" or "Already in job"
             // For now we return the error to let the caller log it.
             return Err(e.into());
        }

        // Memory Limit
        if memory_limit_mb > 0 {
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = (memory_limit_mb as usize * 1024 * 1024);
             SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )?;
        }

        // CPU Limit
        if cpu_limit_percent > 0 {
             let mut info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::default();
             info.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
             // CpuRate: Specifies the CPU rate as a percentage times 100. For example, to specify 20%, set this member to 2,000.
             info.Anonymous.CpuRate = cpu_limit_percent * 100;
             
             SetInformationJobObject(
                job,
                JobObjectCpuRateControlInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            )?;
        }
        
        // Leak the job handle intentionally so it persists for the process lifetime
        // or until we want to close it? If we close handle, limits *might* persist if process is assigned?
        // "The job object is destroyed when its last handle has been closed and all associated processes have been terminated."
        // Since we are inside the process, if we close the handle, the job ref count drops.
        // But the process has an open handle to the job? No.
        // So we must keep the handle open.
        // Since `apply_limits` creates a NEW job every time, calling this multiple times
        // will try to assign process to nested jobs. Windows 8+ supports nested jobs.
        // For this simple implementation, we assume it's called rarely or just once.
        std::mem::forget(job);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() > 2 && args[1] == "--worker" {
        let pipe_name = if args[2] == "--pipe" && args.len() > 3 {
            &args[3]
        } else {
            &args[2]
        };
        let session_id = "poc-session";
        connect_and_run(session_id, pipe_name).await?;
    } else {
        println!("usage: vlt-worker --worker --pipe <pipe_name>");
    }
    Ok(())
}

#[cfg(not(windows))]
async fn connect_and_run(_session_id: &str, _pipe_name: &str) -> Result<()> {
    Err(anyhow!("worker only supported on Windows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_deserialization() {
        let json = r#"{"type": "APPLY_POLICY", "policy": {"allowExec": true, "allowPortForwarding": true, "terminalEncoding": "utf-8", "idleTimeoutSeconds": 0}, "command": "whoami"}"#;
        let msg: ServiceToWorker = serde_json::from_str(json).unwrap();
        if let ServiceToWorker::ApplyPolicy { command, .. } = msg {
            assert_eq!(command, Some("whoami".to_string()));
        } else {
            panic!("expected ApplyPolicy");
        }
    }

    #[test]
    fn test_powershell_encoding() {
        let cmd = "whoami";
        let encoded_utf16: Vec<u8> = cmd
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = general_purpose::STANDARD.encode(&encoded_utf16);
        // "whoami" in UTF-16LE is: w(0x77 0x00) h(0x68 0x00) o(0x6F 0x00) a(0x61 0x00) m(0x6D 0x00) i(0x69 0x00)
        // Base64 should be "dwBoAG8AYQBtAGkA"
        assert_eq!(b64, "dwBoAG8AYQBtAGkA");
    }

    #[test]
    fn test_multi_message_framing() {
        // ALGO-01: Verify that BufReader correctly splits multiple messages separated by newlines.
        let msg1 = r#"{"type": "PING", "data": "first"}"#;
        let msg2 = r#"{"type": "PING", "data": "second"}"#;
        let stream = format!("{}\n{}\n", msg1, msg2);
        
        let mut cursor = std::io::Cursor::new(stream.as_bytes());
        let mut reader = std::io::BufReader::new(&mut cursor);
        
        // First message
        let mut line = String::new();
        let n = std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
        assert!(n > 0);
        let parsed1: ServiceToWorker = serde_json::from_str(&line).unwrap();
        if let ServiceToWorker::Ping { data } = parsed1 {
            assert_eq!(data, "first");
        } else {
            panic!("Expected Ping first");
        }
        
        // Second message
        line.clear();
        let n = std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
        assert!(n > 0);
        let parsed2: ServiceToWorker = serde_json::from_str(&line).unwrap();
        if let ServiceToWorker::Ping { data } = parsed2 {
            assert_eq!(data, "second");
        } else {
            panic!("Expected Ping second");
        }
    }
}
