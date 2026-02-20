use anyhow::{anyhow, Result};
#[cfg(windows)]
use windows::Win32::Foundation::{LocalFree, HLOCAL};
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};

#[cfg(windows)]
const DPAPI_ENTROPY: &[u8] = b"WinNativeSSH-Internal-Secret-Entropy-2026-02";

#[cfg(windows)]
pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: This block uses the DPAPI CryptProtectData function to encrypt data.
    // Pointers to the input and entropy buffers are valid during the call.
    // The output buffer is allocated by the API and is manually freed using LocalFree.
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut entropy = CRYPT_INTEGER_BLOB {
            cbData: DPAPI_ENTROPY.len() as u32,
            pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        // [SEC-02] Fixed: Removed CRYPTPROTECT_LOCAL_MACHINE.
        // Decryption is now restricted to the user context that performed encryption.
        // We also use additional entropy to prevent simple DPAPI decryption by other tools.
        let flags = CRYPTPROTECT_UI_FORBIDDEN;

        CryptProtectData(
            &mut input,
            None,
            Some(&mut entropy),
            None,
            None,
            flags,
            &mut output,
        )
        .map_err(|e| anyhow!("CryptProtectData failed: {:?}", e))?;

        let res = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        local_free(output.pbData as _);
        Ok(res)
    }
}

#[cfg(windows)]
pub fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: This block uses the DPAPI CryptUnprotectData function to decrypt data.
    // Pointers to the input and entropy buffers are valid during the call.
    // The output buffer is allocated by the API and is manually freed using LocalFree.
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut entropy = CRYPT_INTEGER_BLOB {
            cbData: DPAPI_ENTROPY.len() as u32,
            pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let flags = CRYPTPROTECT_UI_FORBIDDEN;

        CryptUnprotectData(
            &mut input,
            None,
            Some(&mut entropy),
            None,
            None,
            flags,
            &mut output,
        )
        .map_err(|e| anyhow!("CryptUnprotectData failed: {:?}", e))?;

        let res = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        local_free(output.pbData as _);
        Ok(res)
    }
}

#[cfg(windows)]
pub fn local_free(ptr: *mut std::ffi::c_void) {
    // SAFETY: This function safely wraps LocalFree for pointers allocated by Win32 APIs.
    unsafe {
        let _ = LocalFree(HLOCAL(ptr));
    }
}

#[cfg(not(windows))]
pub fn protect(_data: &[u8]) -> Result<Vec<u8>> {
    Err(anyhow!("DPAPI not supported on this platform"))
}

#[cfg(not(windows))]
pub fn unprotect(_data: &[u8]) -> Result<Vec<u8>> {
    Err(anyhow!("DPAPI not supported on this platform"))
}
