use crate::sbp::protocol::{SBPRequest, SBPResponse};
use anyhow::Result;
use std::path::PathBuf;

pub struct SBPSession {
    pub current_dir: PathBuf,
}

impl SBPSession {
    pub fn new() -> Self {
        Self {
            current_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("C:\\")),
        }
    }

    pub async fn handle_request(&mut self, req: SBPRequest) -> Result<SBPResponse> {
        match req {
            SBPRequest::Exec {
                version,
                program,
                args,
                cwd: _req_cwd,
            } => {
                let mut cmd = tokio::process::Command::new(&program);
                // Use self.current_dir as strict base
                cmd.current_dir(&self.current_dir);
                cmd.args(args);

                match cmd.output().await {
                   Ok(output) => {
                       let mut data = output.stdout;
                       if !output.stderr.is_empty() {
                           data.extend_from_slice(b"\n--- stderr ---\n");
                           data.extend_from_slice(&output.stderr);
                       }
                       Ok(SBPResponse::Reply {
                           version,
                           data,
                       })
                   }
                   Err(e) => {
                        Ok(SBPResponse::Reply {
                            version,
                            data: format!("Execution failed: {}", e).into_bytes(),
                        })
                   }
                }
            }
            SBPRequest::ChangeDir { version, path } => {
                // Basic implementation - in real world check for traversal
                let new_path = self.current_dir.join(path);
                if new_path.exists() && new_path.is_dir() {
                    self.current_dir = new_path;
                    Ok(SBPResponse::Reply {
                        version,
                        data: format!("CWD changed to {:?}", self.current_dir).into_bytes(),
                    })
                } else {
                     Ok(SBPResponse::Reply {
                        version,
                        data: b"Directory not found".to_vec(),
                    })
                }
            }
            SBPRequest::GetStatus { version } => Ok(SBPResponse::Reply {
                version,
                data: format!("CWD is {:?}", self.current_dir).into_bytes(),
            }),
        }
    }
}
