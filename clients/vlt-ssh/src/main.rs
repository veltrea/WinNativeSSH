use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rpassword::read_password;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

mod auth;
mod config;
mod forward;
mod security;
mod shell;

// Helper functions adapted from vlt-ssh/src/lib.rs that are missing in main.rs context
use ssh2::Session;

// Re-implement print_auth_failure_hints locally or import if we had a lib.rs
// For now, I will inline the necessary helpers from lib.rs into main.rs to avoid circular deps or complex refactors
// in this "lift and shift" phase.

fn print_auth_failure_hints(
    sess: &Session,
    user: &str,
    identity_file: Option<&str>,
    tried_pubkey: bool,
    tried_agent: bool,
    tried_password: bool,
) {
    if let Ok(methods) = sess.auth_methods(user) {
        eprintln!("hint: server auth methods={methods}");
    }

    if let Some(identity_file) = identity_file.filter(|_| tried_pubkey) {
        eprintln!("hint: public key auth failed for key={identity_file}");
    }
    if tried_agent {
        eprintln!("hint: ssh-agent auth was attempted and rejected");
    }
    if tried_password {
        eprintln!("hint: password auth was attempted and rejected");
    }

    if sess
        .banner()
        .is_some_and(|b: &str| b.contains("OpenSSH_for_Windows") && tried_pubkey)
    {
        eprintln!("hint_code=WIN_ACL_AUTHKEYS");
        eprintln!(
            "hint: Windows OpenSSH may reject keys due to authorized_keys ACL. Check OpenSSH/Operational for 'Bad permissions'."
        );
        eprintln!(
            "hint: admin users may require C:\\\\ProgramData\\\\ssh\\\\administrators_authorized_keys with strict ACL."
        );
    }
}

fn parse_destination(
    destination: &str,
    port_override: Option<u16>,
) -> Result<(Option<String>, String, Option<u16>)> {
    let (user_opt, host_port) = if let Some((user, rest)) = destination.split_once('@') {
        (Some(user.to_string()), rest)
    } else {
        (None, destination)
    };

    if let Some(port) = port_override {
        return Ok((user_opt, host_port.to_string(), Some(port)));
    }

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok((user_opt, host.to_string(), Some(port)));
        }
    }

    Ok((user_opt, host_port.to_string(), None))
}

fn parse_local_forward(s: &str) -> Result<(u16, String, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.as_slice() {
        [remote_host, remote_port] => {
            let remote_port = remote_port
                .parse::<u16>()
                .with_context(|| format!("Invalid remote port in -L option: {remote_port}"))?;
            Ok((remote_port, (*remote_host).to_string(), remote_port))
        }
        [local_port, remote_host, remote_port] => {
            let local_port = local_port
                .parse::<u16>()
                .with_context(|| format!("Invalid local port in -L option: {local_port}"))?;
            let remote_port = remote_port
                .parse::<u16>()
                .with_context(|| format!("Invalid remote port in -L option: {remote_port}"))?;
            Ok((local_port, (*remote_host).to_string(), remote_port))
        }
        _ => Err(anyhow!(
            "Invalid -L format. Use [local_port:]remote_host:remote_port"
        )),
    }
}

#[derive(Parser, Debug)]
#[command(name = "vlt-ssh", version = "0.1.0", about = "WinNativeSSH Native Client (vlt-ssh) with M4-Evolve Hybrid Protocol Support", long_about = None)]
struct Args {
    /// Target destination as [user@]host[:port]
    destination: String,

    /// Command to execute on the remote host (optional, starts shell if omitted)
    command: Option<String>,

    /// Identity file (private key) for public key authentication
    #[arg(short = 'i', long)]
    identity_file: Option<String>,

    /// Port to connect to (overrides destination port)
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Local port forwarding as [local_port:]remote_host:remote_port
    #[arg(short = 'L', long)]
    local_forward: Option<String>,

    /// Disable strict host key checking
    #[arg(long)]
    no_strict_checking: bool,

    /// Insecure: skip all host key verification checks (for debugging only)
    #[arg(long)]
    insecure_ignore_host_key: bool,

    /// Set preferred cipher (e.g., aes256-ctr)
    #[arg(short = 'C', long)]
    cipher: Option<String>,

    /// Set preferred key exchange algorithm (e.g., diffie-hellman-group14-sha256)
    #[arg(short = 'K', long)]
    kex: Option<String>,

    /// Password for password authentication (insecure: visible in process args)
    #[arg(long, conflicts_with = "password_stdin")]
    password: Option<String>,

    /// Read password from STDIN for password authentication
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,

    /// Enabled M4 protocol (Argument-Safe Protocol / JSON transport)
    #[arg(long)]
    m4: bool,

    /// Set current working directory for remote execution (M4 only)
    #[arg(long)]
    m4_cwd: Option<String>,

    /// Enabled M4-Evolve protocol (Binary-Native Framing v1)
    #[arg(long)]
    m4_v2: bool,

    /// Emergency restart the remote vlt-sshd service (unstable)
    #[arg(long)]
    restart: bool,
}

#[derive(serde::Serialize)]
struct M4ExecRequest {
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // 1. Initial parsing of destination
    let (user_opt, host, parsed_port): (Option<String>, String, Option<u16>) =
        parse_destination(&args.destination, args.port)?;

    // 2. Load SSH Config and Merge
    let ssh_config = config::load_ssh_config(&host).unwrap_or_default();
    let final_user = user_opt
        .or(ssh_config.user)
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".to_string());
    let final_port = parsed_port.or(ssh_config.port).unwrap_or(22);
    let final_identity = args.identity_file.or(ssh_config.identity_file);
    let final_identity_for_hints = final_identity.clone();

    println!("Connecting to {}@{}:{}...", final_user, host, final_port);

    if args.m4_v2 {
        println!("vlt-ssh: [M4-Evolve] Hybrid Transport Active. Bypassing Windows command-line 'quoting hell' via binary-native framing.");
    } else if args.m4 {
        println!("vlt-ssh: [M4] Argument-Safe Protocol Active. Ensuring safe delivery of complex Windows command arguments.");
    }

    // 3. Establish Connection and Session
    let tcp = TcpStream::connect(format!("{}:{}", host, final_port))
        .with_context(|| format!("Failed to connect to {}:{}", host, final_port))?;
    let mut sess = Session::new()?;

    // Algorithm customization
    if let Some(cipher) = args.cipher {
        sess.method_pref(ssh2::MethodType::CryptSc, &cipher)?;
        sess.method_pref(ssh2::MethodType::CryptCs, &cipher)?;
    }
    if let Some(kex) = args.kex {
        sess.method_pref(ssh2::MethodType::Kex, &kex)?;
    }

    sess.set_tcp_stream(tcp);
    sess.handshake()?;

    // 4. Host Key Verification
    auth::verify_host_key(
        &sess,
        &host,
        final_port,
        !args.no_strict_checking,
        args.insecure_ignore_host_key,
    )?;

    // 5. Authentication
    let mut authenticated = false;
    let mut tried_pubkey = false;
    let mut tried_agent = false;
    let mut tried_password = false;

    if let Some(key_path) = final_identity.as_deref() {
        tried_pubkey = true;
        if sess
            .userauth_pubkey_file(&final_user, None, Path::new(key_path), None)
            .is_ok()
        {
            authenticated = true;
        }
    }

    if !authenticated {
        tried_agent = true;
    }
    if !authenticated && sess.userauth_agent(&final_user).is_ok() {
        authenticated = sess.authenticated();
    }

    if !authenticated {
        if let Some(password) = args.password {
            tried_password = true;
            if let Err(err) = sess.userauth_password(&final_user, &password) {
                print_auth_failure_hints(
                    &sess,
                    &final_user,
                    final_identity_for_hints.as_deref(),
                    tried_pubkey,
                    tried_agent,
                    tried_password,
                );
                return Err(anyhow!("Password authentication failed: {err}"));
            }
            authenticated = sess.authenticated();
        }
    }

    if !authenticated && args.password_stdin {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        let password = buf.trim_end_matches(['\r', '\n']);
        if password.is_empty() {
            return Err(anyhow!(
                "--password-stdin was set but no password was provided on STDIN"
            ));
        }
        tried_password = true;
        if let Err(err) = sess.userauth_password(&final_user, password) {
            print_auth_failure_hints(
                &sess,
                &final_user,
                final_identity_for_hints.as_deref(),
                tried_pubkey,
                tried_agent,
                tried_password,
            );
            return Err(anyhow!("Password authentication failed: {err}"));
        }
        authenticated = sess.authenticated();
    }

    if !authenticated {
        print!("Password for {}@{}: ", final_user, host);
        std::io::stdout().flush()?;
        let password = match read_password() {
            Ok(password) => password,
            Err(err) => {
                print_auth_failure_hints(
                    &sess,
                    &final_user,
                    final_identity_for_hints.as_deref(),
                    tried_pubkey,
                    tried_agent,
                    tried_password,
                );
                eprintln!(
                    "hint: non-interactive session detected. Use --password-stdin if needed."
                );
                return Err(err.into());
            }
        };
        tried_password = true;
        if let Err(err) = sess.userauth_password(&final_user, &password) {
            print_auth_failure_hints(
                &sess,
                &final_user,
                final_identity_for_hints.as_deref(),
                tried_pubkey,
                tried_agent,
                tried_password,
            );
            return Err(anyhow!("Password authentication failed: {err}"));
        }
        authenticated = sess.authenticated();
    }

    if !authenticated {
        print_auth_failure_hints(
            &sess,
            &final_user,
            final_identity_for_hints.as_deref(),
            tried_pubkey,
            tried_agent,
            tried_password,
        );
        return Err(anyhow!("Authentication failed."));
    }

    // 6. Handle Port Forwarding (-L)
    if let Some(forward_str) = args.local_forward {
        let (local_port, remote_host, remote_port) = parse_local_forward(&forward_str)?;
        forward::start_local_forward(&sess, local_port, &remote_host, remote_port)?;
        return Ok(());
    }

    // 7. Handle Command Execution / Shell / Restart
    if args.restart {
        println!("vlt-ssh: [M4-Evolve] Triggering emergency remote server restart...");
        let mut channel = sess.channel_session()?;
        channel.exec("vlt-upgrade-m4")?;

        let mut frame = Vec::with_capacity(5);
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.push(0x05); // Type 0x05: Restart Request
        channel.write_all(&frame)?;

        println!("Restart signal sent. Server connection will be closed.");
        return Ok(());
    }

    if let Some(cmd) = args.command {
        let mut channel = sess.channel_session()?;

        if args.m4_v2 {
            // M4-Evolve Binary-Native Protocol Implementation
            let parts: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
            if parts.is_empty() {
                return Err(anyhow!("M4-v2 mode enabled but no command provided"));
            }

            let request = M4ExecRequest {
                program: parts[0].clone(),
                args: parts[1..].to_vec(),
                cwd: args.m4_cwd,
            };
            let payload = serde_json::to_vec(&request)?;

            channel.exec("vlt-upgrade-m4")?;

            // Send Type 0x01: JSON Request Frame
            let mut frame = Vec::with_capacity(5 + payload.len());
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.push(0x01);
            frame.extend_from_slice(&payload);
            channel.write_all(&frame)?;

            // Receive loop for native frames
            let mut stdout_handle = std::io::stdout();
            let mut stderr_handle = std::io::stderr();

            loop {
                let mut head = [0u8; 5];
                if let Err(_) = channel.read_exact(&mut head) {
                    break;
                }
                let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
                let msg_type = head[4];

                if msg_type == 0xFF {
                    break;
                }

                let mut payload = vec![0u8; len];
                channel.read_exact(&mut payload)?;

                match msg_type {
                    0x02 => {
                        let _ = stdout_handle.write_all(&payload);
                        let _ = stdout_handle.flush();
                    }
                    0x03 => {
                        let _ = stderr_handle.write_all(&payload);
                        let _ = stderr_handle.flush();
                    }
                    _ => {}
                }
            }
        } else if args.m4 {
            // M4 Protocol Implementation
            let parts: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
            if parts.is_empty() {
                return Err(anyhow!("M4 mode enabled but no command provided"));
            }
            let program = parts[0].clone();
            let program_args = parts[1..].to_vec();

            let request = M4ExecRequest {
                program,
                args: program_args,
                cwd: args.m4_cwd,
            };
            let payload = serde_json::to_vec(&request)?;

            channel.exec("vlt-ssh-json")?;
            channel.write_all(&payload)?;
            channel.send_eof()?;
        } else {
            channel.exec(&cmd)?;
        }

        let mut stdout = std::io::stdout();
        let mut stderr = std::io::stderr();
        std::io::copy(&mut channel, &mut stdout)?;
        std::io::copy(&mut channel.stderr(), &mut stderr)?;
        channel.wait_close()?;
        let exit_code = channel.exit_status()?;
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
    } else {
        shell::start_interactive_shell(&sess)?;
    }

    Ok(())
}
