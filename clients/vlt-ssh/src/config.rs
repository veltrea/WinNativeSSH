use anyhow::{Context, Result};
use ssh2_config::{ParseRule, SshConfig};
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, Default)]
pub struct ConfigOverrides {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
}

pub fn load_ssh_config(host: &str) -> Result<ConfigOverrides> {
    let mut config_path = dirs::home_dir().context("Failed to get home directory")?;
    config_path.push(".ssh");
    config_path.push("config");

    if !config_path.exists() {
        return Ok(ConfigOverrides::default());
    }

    let file = File::open(&config_path)?;
    let mut reader = BufReader::new(file);
    let config = SshConfig::default()
        .parse(
            &mut reader,
            ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
        )
        .map_err(|e| anyhow::anyhow!("Failed to parse SSH config: {}", e))?;

    let params = config.query(host);

    Ok(ConfigOverrides {
        user: params.user.clone(),
        port: params.port,
        identity_file: params
            .identity_file
            .as_ref()
            .and_then(|paths| paths.first())
            .map(|p| p.to_string_lossy().into_owned()),
    })
}
