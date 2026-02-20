use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ssh2::{CheckResult, KnownHostKeyFormat, Session};
use std::fs;
use std::io::{stdin, stdout, Write};

fn format_openssh_sha256_fingerprint(hash: Option<&[u8]>) -> String {
    hash.map(|h| format!("SHA256:{}", STANDARD.encode(h)))
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn verify_host_key(
    sess: &Session,
    host: &str,
    port: u16,
    strict: bool,
    insecure_ignore_host_key: bool,
) -> Result<()> {
    if insecure_ignore_host_key {
        eprintln!(
            "WARNING: host key verification is disabled by --insecure-ignore-host-key (debug only)."
        );
        return Ok(());
    }

    let mut known_hosts = sess.known_hosts()?;
    let mut config_path = dirs::home_dir().context("Failed to get home directory")?;
    config_path.push(".ssh");
    fs::create_dir_all(&config_path)?;
    config_path.push("known_hosts");

    if config_path.exists() {
        known_hosts.read_file(&config_path, ssh2::KnownHostFileKind::OpenSSH)?;
    }

    let (key, alg) = sess
        .host_key()
        .ok_or_else(|| anyhow!("Failed to get host key from session"))?;

    match known_hosts.check_port(host, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::NotFound => {
            if strict {
                return Err(anyhow!(
                    "Host key not found in known_hosts and strict checking is enabled."
                ));
            }

            println!(
                "The authenticity of host '{}:{}' can't be established.",
                host, port
            );
            println!(
                "{:?} key fingerprint is {}.",
                alg,
                format_openssh_sha256_fingerprint(sess.host_key_hash(ssh2::HashType::Sha256))
            );

            print!("Are you sure you want to continue connecting (yes/no)? ");
            stdout().flush()?;

            let mut input = String::new();
            stdin().read_line(&mut input)?;
            if input.trim().eq_ignore_ascii_case("yes") {
                let format: KnownHostKeyFormat = alg.into();
                if matches!(format, KnownHostKeyFormat::Unknown) {
                    return Err(anyhow!("Unsupported host key type: {:?}", alg));
                }

                let host_for_known_hosts = if port == 22 {
                    host.to_string()
                } else {
                    format!("[{}]:{}", host, port)
                };

                known_hosts.add(&host_for_known_hosts, key, "Added by rust-ssh", format)?;
                known_hosts.write_file(&config_path, ssh2::KnownHostFileKind::OpenSSH)?;
                Ok(())
            } else {
                Err(anyhow!("Host key verification failed."))
            }
        }
        CheckResult::Mismatch => Err(anyhow!(
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
             @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!    @\n\
             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
             IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!"
        )),
        CheckResult::Failure => Err(anyhow!("Unknown error during host key verification.")),
    }
}

#[cfg(test)]
mod tests {
    use super::format_openssh_sha256_fingerprint;

    #[test]
    fn fingerprint_formats_to_openssh_style() {
        let fp = format_openssh_sha256_fingerprint(Some(&[0x00, 0x01, 0x02]));
        assert_eq!(fp, "SHA256:AAEC");
    }

    #[test]
    fn fingerprint_unknown_when_missing() {
        let fp = format_openssh_sha256_fingerprint(None);
        assert_eq!(fp, "unknown");
    }
}
