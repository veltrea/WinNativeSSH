use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal,
};
use ssh2::Session;
use std::io::{Read, Write};
use std::thread;
use std::time::Duration;

struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

pub fn start_interactive_shell(sess: &Session) -> Result<()> {
    let mut channel = sess.channel_session()?;

    let (cols, rows) = terminal::size().context("Failed to get terminal size")?;
    channel.request_pty(
        "xterm-256color",
        None,
        Some((cols as u32, rows as u32, 0, 0)),
    )?;
    channel.shell()?;

    terminal::enable_raw_mode().context("Failed to enable raw mode")?;
    let _raw_mode_guard = RawModeGuard;

    let mut channel_reader = channel.stream(0);
    let mut channel_writer = channel.stream(0);
    let mut resize_channel = channel.clone();

    let reader_handle = thread::spawn(move || {
        let mut out = std::io::stdout();
        let mut buf = [0u8; 4096];
        loop {
            match channel_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out.write_all(&buf[..n]).is_err() || out.flush().is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        if event::poll(Duration::from_millis(10))? {
            match event::read()? {
                Event::Resize(new_cols, new_rows) => {
                    resize_channel.request_pty_size(
                        new_cols as u32,
                        new_rows as u32,
                        None,
                        None,
                    )?;
                }
                Event::Key(KeyEvent {
                    code, modifiers, ..
                }) => {
                    match code {
                        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                            channel_writer.write_all(&[3])?;
                        }
                        KeyCode::Char(c) => {
                            let mut b = [0u8; 4];
                            let s = c.encode_utf8(&mut b);
                            channel_writer.write_all(s.as_bytes())?;
                        }
                        KeyCode::Enter => channel_writer.write_all(b"\r")?,
                        KeyCode::Backspace => channel_writer.write_all(&[8])?,
                        KeyCode::Tab => channel_writer.write_all(&[9])?,
                        KeyCode::Esc => channel_writer.write_all(&[27])?,
                        KeyCode::Left => channel_writer.write_all(b"\x1b[D")?,
                        KeyCode::Right => channel_writer.write_all(b"\x1b[C")?,
                        KeyCode::Up => channel_writer.write_all(b"\x1b[A")?,
                        KeyCode::Down => channel_writer.write_all(b"\x1b[B")?,
                        _ => {}
                    }
                    channel_writer.flush()?;
                }
                _ => {}
            }
        }

        if reader_handle.is_finished() {
            break;
        }
    }

    let _ = reader_handle.join();
    Ok(())
}
