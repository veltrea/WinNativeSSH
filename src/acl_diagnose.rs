use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Japanese,
    English,
}

impl Default for Language {
    fn default() -> Self {
        #[cfg(windows)]
        {
            if is_japanese_locale() {
                Language::Japanese
            } else {
                Language::English
            }
        }
        #[cfg(not(windows))]
        Language::English
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclDiagnosis {
    pub path: String,
    pub is_valid: bool,
    pub failure_reason: Option<String>,
    pub details: Vec<String>,
    pub diagnostics: AclDetails,
    pub language: Language,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AclDetails {
    pub owner: String,
    pub is_inherited: bool,
    pub entries: Vec<AclEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub identity: String,
    pub rights: String,
    pub access_type: String,
}

impl AclDiagnosis {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_string_lossy().to_string(),
            is_valid: true,
            failure_reason: None,
            details: Vec::new(),
            diagnostics: AclDetails::default(),
            language: Language::default(),
        }
    }

    pub fn fail(&mut self, reason: &str) {
        self.is_valid = false;
        self.failure_reason = Some(reason.to_string());
    }

    pub fn add_detail(&mut self, detail: &str) {
        self.details.push(detail.to_string());
    }
}

/// 指定されたパスの ACL を Windows API で直接診断する（外部プロセス不使用）
#[cfg(windows)]
pub fn diagnose_path(path: &Path, expected_owner_sid: Option<&str>) -> Result<AclDiagnosis> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL, PSID};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACE_HEADER,
        DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL, SE_DACL_PROTECTED,
    };

    let mut diag = AclDiagnosis::new(path);

    if !path.exists() {
        diag.fail("Path does not exist");
        return Ok(diag);
    }

    // パスを UTF-16 null 終端に変換（worker_broker.rs と同じパターン）
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: This block uses GetNamedSecurityInfoW to retrieve the security descriptor (SD) 
    // of a file. The SD is allocated by the API and must be freed with LocalFree, 
    // which is handled by the SdGuard (RAII).
    unsafe {
        let mut p_owner: PSID = PSID::default();
        let mut p_dacl: *mut windows::Win32::Security::ACL = ptr::null_mut();
        let mut p_sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();

        // ACL と所有者を取得（外部プロセス不使用、Windows API 直接呼び出し）
        let err = GetNamedSecurityInfoW(
            PCWSTR(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0),
            Some(&mut p_owner),
            None, // group 不要
            Some(&mut p_dacl),
            None, // sacl 不要
            &mut p_sd,
        );

        if err.is_err() {
            diag.fail(&format!("GetNamedSecurityInfoW failed: {:?}", err));
            return Ok(diag);
        }

        // RAII: p_sd は GetNamedSecurityInfoW が確保したメモリ。
        // この関数の最後で必ず LocalFree する。
        // scopeguard 的に defer で保証。
        struct SdGuard(PSECURITY_DESCRIPTOR);
        impl Drop for SdGuard {
            fn drop(&mut self) {
                // SAFETY: p_sd was allocated by GetNamedSecurityInfoW and must be released 
                // using LocalFree to prevent memory leaks.
                unsafe {
                    if !self.0 .0.is_null() {
                        let _ = LocalFree(HLOCAL(self.0 .0));
                    }
                }
            }
        }
        let _sd_guard = SdGuard(p_sd);

        // ===== 所有者 SID を文字列に変換 =====
        let owner_sid_str = sid_to_string_sid(p_owner);
        let owner_account = sid_to_account_name(p_owner);

        let owner_display = if let Some(ref acct) = owner_account {
            acct.clone()
        } else if let Some(ref sid) = owner_sid_str {
            sid.clone()
        } else {
            "unknown".to_string()
        };

        diag.diagnostics.owner = owner_display.clone();
        diag.add_detail(&format!("Owner: {}", owner_display));

        // ===== 所有者 SID の検証 =====
        if let Some(expected) = expected_owner_sid {
            if let Some(ref actual_sid) = owner_sid_str {
                if !actual_sid.eq_ignore_ascii_case(expected) {
                    // SYSTEM (S-1-5-18) と Administrators (S-1-5-32-544) は許容
                    let is_system = actual_sid == "S-1-5-18";
                    let is_admins = actual_sid == "S-1-5-32-544";
                    if !is_system && !is_admins {
                        diag.fail(&format!(
                            "Owner mismatch: expected SID {} but got {}",
                            expected, actual_sid
                        ));
                    }
                }
            }
        } else if path.to_string_lossy().contains("ProgramData\\ssh") {
            // 管理者用パスの場合は SYSTEM または Administrators のみを許可
            if let Some(ref actual_sid) = owner_sid_str {
                let is_system = actual_sid == "S-1-5-18";
                let is_admins = actual_sid == "S-1-5-32-544";
                if !is_system && !is_admins {
                    diag.fail(&format!(
                        "Security risk for System Path: Administrative path must be owned by SYSTEM or Administrators, but got {}",
                        actual_sid
                    ));
                }
            }
        }

        // ===== 継承フラグの確認 =====
        let mut control = SECURITY_DESCRIPTOR_CONTROL::default();
        let mut revision: u32 = 0;
        // SAFETY: GetSecurityDescriptorControl is a safe read from a valid security descriptor.
        if GetSecurityDescriptorControl(p_sd, &mut control.0, &mut revision).is_ok() {
            // SE_DACL_PROTECTED が設定されていれば継承は無効（OpenSSH が求める状態）
            let is_protected = (control.0 & SE_DACL_PROTECTED.0) != 0;
            diag.diagnostics.is_inherited = !is_protected;
            if !is_protected {
                diag.fail(
                    "Inheritance is enabled. OpenSSH requires explicit (non-inherited) ACLs.",
                );
            }
        }

        // ===== DACL エントリの列挙 =====
        if !p_dacl.is_null() {
            // SAFETY: p_dacl is a valid pointer to an ACL structure returned by GetNamedSecurityInfoW.
            let acl_ref = &*p_dacl;
            let ace_count = acl_ref.AceCount as u32;

            for i in 0..ace_count {
                let mut p_ace: *mut std::ffi::c_void = ptr::null_mut();
                // SAFETY: GetAce is used within the bounds of AceCount. 
                // p_ace is an output pointer that will point into the ACL.
                if GetAce(p_dacl, i, &mut p_ace).is_err() {
                    continue;
                }

                // SAFETY: ACE_HEADER is the common prefix of all ACE types.
                let ace_header = &*(p_ace as *const ACE_HEADER);
                // ACCESS_ALLOWED_ACE (type 0) と ACCESS_DENIED_ACE (type 1) を処理
                // どちらも先頭の構造が同じ (Header, Mask, SidStart)
                let access_type = match ace_header.AceType {
                    0 => "Allow",
                    1 => "Deny",
                    _ => "Other",
                };

                // ACCESS_ALLOWED_ACE の Mask と SidStart を読む
                // SAFETY: ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share the same structure 
                // for the fields we access here.
                let allowed_ace = &*(p_ace as *const ACCESS_ALLOWED_ACE);
                let mask = allowed_ace.Mask;
                let sid_ptr = PSID(&allowed_ace.SidStart as *const u32 as *mut std::ffi::c_void);

                let identity = sid_to_account_name(sid_ptr)
                    .or_else(|| sid_to_string_sid(sid_ptr))
                    .unwrap_or_else(|| "unknown".to_string());

                let rights = format_access_mask(mask);

                diag.diagnostics.entries.push(AclEntry {
                    identity: identity.clone(),
                    rights,
                    access_type: access_type.to_string(),
                });
            }
        }

        diag.check_security_risks();
    }

    Ok(diag)
}

/// 指定されたパスからルートに向かって再帰的に権限をチェックする
#[cfg(windows)]
pub fn check_path_recursion(
    start_path: &Path,
    expected_owner_sid: Option<&str>,
) -> Vec<AclDiagnosis> {
    let mut results = Vec::new();
    let mut current_path = start_path.to_path_buf();

    while let Some(parent) = current_path.parent() {
        // ルート (C:\ 等) に達したら終了。通常、ユーザープロファイルより上はシステム管理。
        if parent.as_os_str().is_empty() {
            break;
        }

        match diagnose_path(&current_path, expected_owner_sid) {
            Ok(diag) => {
                results.push(diag);
            }
            Err(e) => {
                let mut diag = AclDiagnosis::new(&current_path);
                diag.fail(&format!("Failed to diagnose path: {}", e));
                results.push(diag);
            }
        }

        // 次の親階層へ
        current_path = parent.to_path_buf();

        // C:\Users 等まで到達したら止める（環境によって調整が必要だが、一旦ここまで）
        if current_path.ends_with(std::path::Path::new("Users")) || current_path.parent().is_none() {
            // ルートディレクトリ自体のチェックを行って終了
            if let Ok(diag) = diagnose_path(&current_path, expected_owner_sid) {
                results.push(diag);
            }
            break;
        }
    }

    results
}

impl AclDiagnosis {
    /// 診断されたエントリの中にセキュリティリスク（広すぎる権限）がないかチェックする
    fn check_security_risks(&mut self) {
        let mut risks = Vec::new();
        for entry in &self.diagnostics.entries {
            if entry.access_type != "Allow" {
                continue;
            }
            let ident_lower = entry.identity.to_lowercase();
            // Everyone, BUILTIN\Users, Authenticated Users への書き込み許可は危険
            let is_broad = ident_lower.contains("everyone")
                || ident_lower == "s-1-1-0"
                || ident_lower.contains("builtin\\users")
                || ident_lower == "s-1-5-32-545"
                || ident_lower.contains("authenticated users")
                || ident_lower == "s-1-5-11";

            if is_broad {
                let rights_lower = entry.rights.to_lowercase();
                let is_writable = rights_lower.contains("write")
                    || rights_lower.contains("fullcontrol")
                    || rights_lower.contains("delete")
                    || rights_lower.contains("changepermissions")
                    || rights_lower.contains("takeownership");

                if is_writable {
                    risks.push(entry.identity.clone());
                }
            }
        }

        for ident in risks {
            self.fail(&format!("Security risk: Broad access granted to {}", ident));
        }
    }

    /// 診断結果に基づき、修復のためのアドバイス（コマンド例等）を多言語で取得する
    pub fn get_repair_advice(&self) -> Vec<String> {
        let mut advices = Vec::new();
        let is_jp = self.language == Language::Japanese;

        if !self.is_valid {
            if let Some(reason) = &self.failure_reason {
                if reason.contains("Inheritance is enabled") {
                    if is_jp {
                        advices.push("継承を無効化してください。".to_string());
                        advices.push(format!(
                            "コマンド例: icacls \"{}\" /inheritance:r",
                            self.path
                        ));
                    } else {
                        advices.push("Please disable inheritance.".to_string());
                        advices.push(format!("Example: icacls \"{}\" /inheritance:r", self.path));
                    }
                }
                if reason.contains("Owner mismatch") {
                    if is_jp {
                        advices.push("所有者が不適切です。適切なユーザー、SYSTEM、または Administrators に設定してください。".to_string());
                        advices.push(format!(
                            "コマンド例: icacls \"{}\" /setowner Administrators",
                            self.path
                        ));
                    } else {
                        advices.push(
                            "Incorrect owner. Set to appropriate user, SYSTEM, or Administrators."
                                .to_string(),
                        );
                        advices.push(format!(
                            "Example: icacls \"{}\" /setowner Administrators",
                            self.path
                        ));
                    }
                }
                if reason.contains("Security risk") {
                    if is_jp {
                        advices.push(
                            "不要なグループ（Everyone, Users 等）への権限を削除してください。"
                                .to_string(),
                        );
                        advices.push(format!(
                            "コマンド例: icacls \"{}\" /remove:g Everyone",
                            self.path
                        ));
                    } else {
                        advices.push(
                            "Remove permissions for unnecessary groups (Everyone, Users, etc.)."
                                .to_string(),
                        );
                        advices.push(format!(
                            "Example: icacls \"{}\" /remove:g Everyone",
                            self.path
                        ));
                    }
                }
            }
        }

        advices
    }
}

/// SID → "S-1-5-21-..." 文字列変換
#[cfg(windows)]
fn sid_to_string_sid(psid: windows::Win32::Foundation::PSID) -> Option<String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

    // SAFETY: ConvertSidToStringSidW allocates a string that must be freed with LocalFree.
    unsafe {
        let mut string_sid = windows::core::PWSTR::null();
        if ConvertSidToStringSidW(psid, &mut string_sid).is_ok() {
            let result = string_sid.to_string().ok();
            let _ = LocalFree(HLOCAL(string_sid.0 as *mut std::ffi::c_void));
            result
        } else {
            None
        }
    }
}

/// SID → "DOMAIN\Account" 名前解決
#[cfg(windows)]
fn sid_to_account_name(psid: windows::Win32::Foundation::PSID) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};

    // SAFETY: LookupAccountSidW is called twice, first to probe for size and then to fill buffers.
    unsafe {
        let mut name_len: u32 = 0;
        let mut domain_len: u32 = 0;
        let mut sid_type = SID_NAME_USE::default();

        // 1回目: バッファサイズ取得
        let _ = LookupAccountSidW(
            PCWSTR::null(),
            psid,
            windows::core::PWSTR::null(),
            &mut name_len,
            windows::core::PWSTR::null(),
            &mut domain_len,
            &mut sid_type,
        );

        if name_len == 0 {
            return None;
        }

        let mut name_buf = vec![0u16; name_len as usize];
        let mut domain_buf = vec![0u16; domain_len as usize];

        // 2回目: 実際の名前解決
        if LookupAccountSidW(
            PCWSTR::null(),
            psid,
            windows::core::PWSTR(name_buf.as_mut_ptr()),
            &mut name_len,
            windows::core::PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_len,
            &mut sid_type,
        )
        .is_ok()
        {
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
            if domain.is_empty() {
                Some(name)
            } else {
                Some(format!("{}\\{}", domain, name))
            }
        } else {
            None
        }
    }
}

/// 実行環境のロケールが日本語かどうかを判定する
#[cfg(windows)]
fn is_japanese_locale() -> bool {
    use windows::Win32::Globalization::GetUserDefaultUILanguage;

    // SAFETY: GetUserDefaultUILanguage is a side-effect free Win32 API call.
    unsafe {
        let lang_id = GetUserDefaultUILanguage();
        // LANG_JAPANESE は 0x11。Primary Language ID を抽出 (lang_id & 0x3ff)
        const LANG_JAPANESE: u16 = 0x11;
        (lang_id & 0x3ff) == LANG_JAPANESE
    }
}

/// アクセスマスクを人間が読める文字列に変換
#[cfg(windows)]
fn format_access_mask(mask: u32) -> String {
    // 主要なファイル権限のビットフラグ
    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_WRITE_DATA: u32 = 0x0002;
    const FILE_EXECUTE: u32 = 0x0020;
    const DELETE: u32 = 0x00010000;
    const WRITE_DAC: u32 = 0x00040000;
    const WRITE_OWNER: u32 = 0x00080000;


    const GENERIC_ALL: u32 = 0x10000000;
    const FILE_ALL_ACCESS: u32 = 0x001F01FF;

    if mask == GENERIC_ALL || mask == FILE_ALL_ACCESS || mask == 0x1F01FF {
        return "FullControl".to_string();
    }

    let mut parts = Vec::new();
    if mask & FILE_READ_DATA != 0 {
        parts.push("Read");
    }
    if mask & FILE_WRITE_DATA != 0 {
        parts.push("Write");
    }
    if mask & FILE_EXECUTE != 0 {
        parts.push("Execute");
    }
    if mask & DELETE != 0 {
        parts.push("Delete");
    }
    if mask & WRITE_DAC != 0 {
        parts.push("ChangePermissions");
    }
    if mask & WRITE_OWNER != 0 {
        parts.push("TakeOwnership");
    }

    if parts.is_empty() {
        format!("0x{:08X}", mask)
    } else {
        parts.join(", ")
    }
}

#[cfg(not(windows))]
pub fn diagnose_path(_path: &Path, _expected_owner_sid: Option<&str>) -> Result<AclDiagnosis> {
    Err(anyhow!("ACL diagnosis is only supported on Windows."))
}
