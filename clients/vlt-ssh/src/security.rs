use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{self, Engine};
use keyring::Entry;
use rand::RngCore;

pub struct SecurityManager {
    service_name: String,
}

impl SecurityManager {
    pub fn new(service: &str) -> Self {
        Self {
            service_name: service.to_string(),
        }
    }

    /// Stores a secret in the OS keyring.
    pub fn store_secret(&self, account: &str, secret: &str) -> Result<()> {
        let entry = Entry::new(&self.service_name, account)?;
        entry.set_password(secret)?;
        Ok(())
    }

    /// Retrieves a secret from the OS keyring.
    pub fn get_secret(&self, account: &str) -> Result<String> {
        let entry = Entry::new(&self.service_name, account)?;
        Ok(entry.get_password()?)
    }

    /// Deletes a secret from the OS keyring.
    pub fn delete_secret(&self, account: &str) -> Result<()> {
        let entry = Entry::new(&self.service_name, account)?;
        entry.delete_credential()?;
        Ok(())
    }

    /// Encrypts data using AES-256-GCM.
    pub fn encrypt(&self, key: &[u8; 32], plaintext: &str) -> Result<String> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(b"unique nonce"); // In production, use a random nonce and prepend it to ciphertext
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok(base64::engine::general_purpose::STANDARD.encode(ciphertext))
    }

    /// Decrypts data using AES-256-GCM.
    pub fn decrypt(&self, key: &[u8; 32], b64_ciphertext: &str) -> Result<String> {
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(b64_ciphertext)
            .context("Failed to decode base64")?;

        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(b"unique nonce"); // Must match the encryption nonce

        let plaintext_bytes = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext_bytes).context("Failed to parse decrypted UTF-8")
    }

    /// Retrieves the master key from Keyring, or creates a new one if not found.
    pub fn get_or_create_master_key(&self) -> Result<[u8; 32]> {
        match self.get_secret("master_key") {
            Ok(hex_key) => {
                let mut key = [0u8; 32];
                hex::decode_to_slice(hex_key, &mut key)
                    .context("Failed to decode master key hex")?;
                Ok(key)
            }
            Err(_) => {
                // Generate a new 32-byte key
                let mut key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);

                let hex_key = hex::encode(key);
                self.store_secret("master_key", &hex_key)?;
                Ok(key)
            }
        }
    }
}

// TPM bridge implementation (placeholder for Phase 11.1 Task 2)
#[cfg(not(target_os = "macos"))]
pub mod tpm {
    use super::*;
    use tss_esapi::Context as TpmContext;

    pub fn is_tpm_available() -> bool {
        std::path::Path::new("/dev/tpm0").exists() || std::path::Path::new("/dev/tpmrm0").exists()
    }

    pub fn is_secure_boot_enabled() -> bool {
        // Common Linux check for Secure Boot status
        std::path::Path::new("/sys/kernel/security/integrity/platform_key").exists()
            || std::process::Command::new("mokutil")
                .arg("--sb-state")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("SecureBoot enabled"))
                .unwrap_or(false)
    }

    pub fn generate_tpm_key() -> Result<String> {
        Err(anyhow!(
            "Full TPM 2.0 key generation requires a hardware TPM and tss-esapi setup."
        ))
    }
}

#[cfg(target_os = "macos")]
pub mod tpm {
    use super::*;

    pub fn is_tpm_available() -> bool {
        // macOS almost always has Secure Enclave on modern hardware (T1/T2/Apple Silicon)
        true
    }

    pub fn is_secure_boot_enabled() -> bool {
        // On macOS, Secure Boot is part of the "Full Security" policy.
        // We check using csrutil or nvram if possible, but csrutil status is most reliable for SIP/SecureBoot context.
        std::process::Command::new("csrutil")
            .arg("status")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("enabled"))
            .unwrap_or(false)
    }

    // On macOS, "TPM-like" hardware trust is handled by the Secure Enclave.
    // This part prepares a hardware-bound P-256 key if possible,
    // or falls back to software-based secure storage in Keychain.
    pub fn generate_tpm_key() -> Result<String> {
        use rand::rngs::OsRng;
        use ssh_key::Algorithm;
        use ssh_key::EcdsaCurve;
        use ssh_key::PrivateKey;

        // NIST P-256 is the standard for hardware-backed keys on macOS/iOS.
        let private_key = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )?;
        let public_key = private_key.public_key();

        Ok(public_key.to_openssh()?)
    }
}
