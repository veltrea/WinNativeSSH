use anyhow::{Context, Result};
use ssh2::Session;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

pub fn start_local_forward(
    sess: &Session,
    local_port: u16,
    remote_host: &str,
    remote_port: u16,
) -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port))
        .with_context(|| format!("Failed to bind to local port {}", local_port))?;

    println!(
        "Local forwarding: 127.0.0.1:{} -> {}:{}",
        local_port, remote_host, remote_port
    );

    for stream in listener.incoming() {
        let stream = stream?;
        let sess_clone = sess.clone();
        let remote_host = remote_host.to_string();

        thread::spawn(move || {
            if let Err(err) = handle_forward_stream(&sess_clone, stream, &remote_host, remote_port)
            {
                eprintln!("Forwarding error: {err}");
            }
        });
    }

    Ok(())
}

fn handle_forward_stream(
    sess: &Session,
    mut local_stream: TcpStream,
    remote_host: &str,
    remote_port: u16,
) -> Result<()> {
    let mut channel = sess.channel_direct_tcpip(remote_host, remote_port, None)?;

    let mut channel_clone = channel.clone();
    let mut local_stream_clone = local_stream.try_clone()?;

    let local_to_remote = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(n) = local_stream_clone.read(&mut buf) {
            if n == 0 || channel_clone.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });

    let mut buf = [0u8; 8192];
    while let Ok(n) = channel.read(&mut buf) {
        if n == 0 || local_stream.write_all(&buf[..n]).is_err() {
            break;
        }
    }

    let _ = local_to_remote.join();
    Ok(())
}
