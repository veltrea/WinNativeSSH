use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub enum ClientOS {
    Windows,
    MacOS,
    Linux,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum PreferredEncoding {
    #[default]
    Utf8,
    Cp932,
    Unknown,
}

impl FromStr for PreferredEncoding {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "UTF-8" | "UTF8" => Ok(Self::Utf8),
            "CP932" | "SHIFT_JIS" | "SHIFT-JIS" | "SJIS" => Ok(Self::Cp932),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub software_version: String,
    pub os: ClientOS,
    pub suggested_encoding: PreferredEncoding,
}

impl ClientInfo {
    pub fn new(version_string: &str) -> Self {
        let version_string = version_string.trim();
        let (os, encoding) = Self::detect_os_and_encoding(version_string);

        ClientInfo {
            software_version: version_string.to_string(),
            os,
            suggested_encoding: encoding,
        }
    }

    fn detect_os_and_encoding(v: &str) -> (ClientOS, PreferredEncoding) {
        let v_lower = v.to_lowercase();

        // OS detection based on software version comments
        let os = if v_lower.contains("windows") || v_lower.contains("ms-openssh") {
            ClientOS::Windows
        } else if v_lower.contains("apple") || v_lower.contains("macos") {
            ClientOS::MacOS
        } else if v_lower.contains("linux")
            || v_lower.contains("ubuntu")
            || v_lower.contains("debian")
        {
            ClientOS::Linux
        } else {
            ClientOS::Unknown
        };

        // Encoding suggestion
        // Windows clients might default to CP932 in older versions or specific setups,
        // but modern OpenSSH for Windows and WSL often use UTF-8.
        // This is a "best guess" which will be refined by channel requests later.
        let encoding = match os {
            ClientOS::Windows | ClientOS::MacOS | ClientOS::Linux | ClientOS::Unknown => {
                PreferredEncoding::Utf8
            }
        };

        (os, encoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let mac = ClientInfo::new("SSH-2.0-OpenSSH_9.6p1 Apple_20240408");
        assert_eq!(mac.os, ClientOS::MacOS);
        assert_eq!(mac.suggested_encoding, PreferredEncoding::Utf8);

        let win = ClientInfo::new("SSH-2.0-OpenSSH_for_Windows_9.5");
        assert_eq!(win.os, ClientOS::Windows);
        assert_eq!(win.suggested_encoding, PreferredEncoding::Utf8);
    }
}
