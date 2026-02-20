use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SBPRequest {
    #[serde(rename = "exec")]
    Exec {
        #[serde(default = "default_version")]
        version: String,
        program: String,
        args: Vec<String>,
        cwd: Option<String>,
    },
    #[serde(rename = "cd")]
    ChangeDir {
        #[serde(default = "default_version")]
        version: String,
        path: String,
    },
    #[serde(rename = "status")]
    GetStatus {
        #[serde(default = "default_version")]
        version: String,
    },
}

fn default_version() -> String {
    "v1".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SBPResponse {
    #[serde(rename = "reply")]
    Reply {
        version: String,
        #[serde(with = "base64_vec")]
        data: Vec<u8>,
    },
    #[serde(rename = "exit")]
    Exit { version: String, code: i32 },
    #[serde(rename = "error")]
    Error { version: String, message: String },
}

mod base64_vec {
    use base64::{engine::general_purpose, Engine as _};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = general_purpose::STANDARD.encode(bytes);
        s.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}
