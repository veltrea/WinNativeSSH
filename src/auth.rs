use log::info;
#[cfg(windows)]
use log::{error, warn};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID, PSID};
#[cfg(windows)]
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, EqualSid, GetTokenInformation, LogonUserW,
    LookupPrivilegeValueW, SecurityImpersonation, SetTokenInformation, TokenPrimary,
    TokenSessionId, TokenUser, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TOKEN_USER,
};
#[cfg(windows)]
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
#[cfg(windows)]
use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
#[cfg(windows)]
use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
#[cfg(windows)]
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};
#[cfg(windows)]
use windows::Win32::UI::Shell::{LoadUserProfileW, UnloadUserProfile, PROFILEINFOW};

pub struct UserToken {
    #[cfg(windows)]
    pub handle: HANDLE,
    #[cfg(windows)]
    pub profile_handle: Option<HANDLE>,
}

#[cfg(windows)]
impl Drop for UserToken {
    fn drop(&mut self) {
        // SAFETY: Closing Windows handles and unloading user profiles are necessary for resource cleanup.
        // The handles are owned by UserToken and valid during its lifetime.
        unsafe {
            if let Some(hprofile) = self.profile_handle.take() {
                if !hprofile.is_invalid() {
                    let _ = UnloadUserProfile(self.handle, hprofile);
                }
            }
            let _ = CloseHandle(self.handle);
        }
    }
}

// SAFETY: UserToken contains Windows HANDLEs which are pointer-sized values.
// In Windows, handles are generally thread-safe to close from any thread or pass between threads,
// provided they are not used simultaneously in a way that violates their specific API constraints.
// For the purposes of this SSH server, Send/Sync is required for async task management.
unsafe impl Send for UserToken {}
unsafe impl Sync for UserToken {}

#[derive(Default)]
pub struct SpawnOptions {
    pub application_name: Option<String>,
    pub command_line: String,
    pub working_dir: Option<String>,
    pub username: Option<String>,
}

pub struct WindowsAuth;

impl WindowsAuth {
    #[cfg(windows)]
    fn token_session_id(token: HANDLE) -> Option<u32> {
        // SAFETY: GetTokenInformation is a standard Win32 API.
        // We handle the buffer allocation and size check correctly.
        unsafe {
            let mut needed = 0u32;
            // Probe for size.
            let _ = GetTokenInformation(token, TokenSessionId, None, 0, &mut needed);
            if needed == 0 {
                return None;
            }
            let mut buf = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TokenSessionId,
                Some(buf.as_mut_ptr() as *mut _),
                needed,
                &mut needed,
            )
            .is_err()
            {
                return None;
            }
            Some(*(buf.as_ptr() as *const u32))
        }
    }

    #[cfg(windows)]
    fn duplicate_primary_token(token: HANDLE) -> anyhow::Result<HANDLE> {
        // SAFETY: DuplicateTokenEx is used to create a primary token from an existing one.
        // The handle is correctly initialized and ownership is managed by the caller.
        unsafe {
            let mut primary = HANDLE::default();
            // Minimal rights we need for CreateProcessAsUserW + session-id adjustment.
            let access = TOKEN_ACCESS_MASK(
                (TOKEN_ASSIGN_PRIMARY.0
                    | TOKEN_DUPLICATE.0
                    | TOKEN_QUERY.0
                    | TOKEN_ADJUST_SESSIONID.0) as u32,
            );
            DuplicateTokenEx(
                token,
                access,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut primary,
            )?;
            Ok(primary)
        }
    }

    #[cfg(windows)]
    fn token_user_sid_ptr(token: HANDLE) -> anyhow::Result<(Vec<u8>, PSID)> {
        // SAFETY: GetTokenInformation is called with correct parameters.
        // The returned PSID points into the allocated buffer (Vec<u8>), which is returned
        // alongside the PSID to ensure data longevity.
        unsafe {
            let mut needed = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
            if needed == 0 {
                return Err(anyhow::anyhow!(
                    "GetTokenInformation(TokenUser) probe failed"
                ));
            }
            let mut buf = vec![0u8; needed as usize];
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                needed,
                &mut needed,
            )?;
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            Ok((buf, tu.User.Sid))
        }
    }

    #[cfg(windows)]
    pub fn authenticate(user: &str, pass: &str) -> Option<UserToken> {
        let user_u16: Vec<u16> = OsStr::new(user)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let pass_u16: Vec<u16> = OsStr::new(pass)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let domain_u16: Vec<u16> = vec![0]; // Local account

        let mut token_handle = HANDLE::default();

        // SAFETY: LogonUserW is used to authenticate the user and obtain a token.
        // Input strings are null-terminated wide strings. The handle is safely stored
        // in UserToken which manages its lifecycle.
        unsafe {
            let res = LogonUserW(
                windows::core::PCWSTR(user_u16.as_ptr()),
                windows::core::PCWSTR(domain_u16.as_ptr()),
                windows::core::PCWSTR(pass_u16.as_ptr()),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token_handle,
            );

            if res.is_ok() {
                info!("Windows authentication successful for user: {}", user);
                Some(UserToken {
                    handle: token_handle,
                    profile_handle: None,
                })
            } else {
                error!("Windows authentication failed for user: {}", user);
                None
            }
        }
    }

    #[cfg(windows)]
    pub fn spawn_as_user(token: &mut UserToken, opts: SpawnOptions) -> anyhow::Result<u32> {
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let app_u16 = opts.application_name.as_ref().map(|s| {
            OsStr::new(s)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        });
        // IMPORTANT: CreateProcess* may mutate the command line buffer; rebuild it per-attempt.
        let cmd_line = opts.command_line.clone();
        let dir_u16 = opts.working_dir.as_ref().map(|s| {
            OsStr::new(s)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        });

        // SAFETY: This block contains various Win32 calls for process creation (CreateProcessAsUserW, CreateProcessWithTokenW),
        // environment block management, and token manipulation. All pointers are valid, handles are correctly checked,
        // and buffers are null-terminated.
        unsafe {
            // Use CreateProcessWithTokenW which requires fewer privileges (SeImpersonatePrivilege)
            // compared to CreateProcessAsUserW (SeAssignPrimaryTokenPrivilege).
            use windows::Win32::System::Threading::{CreateProcessWithTokenW, LOGON_WITH_PROFILE};

            // If we can move the user token into the active console session, do so and prefer
            // CreateProcessAsUserW. Many GUI-ish or subsystem-heavy binaries (PowerShell, WSL, etc.)
            // behave differently when started in Session 0.
            let active_session = WTSGetActiveConsoleSessionId();
            if active_session != u32::MAX {
                let token_sid = Self::token_session_id(token.handle).unwrap_or(u32::MAX);
                info!(
                    "spawn_as_user: token_session_id={} active_console_session_id={}",
                    token_sid, active_session
                );
            } else {
                warn!(
                    "spawn_as_user: WTSGetActiveConsoleSessionId returned -1 (no active session?)"
                );
            }

            if token.profile_handle.is_none() {
                if let Some(ref username) = opts.username {
                    let username_wide: Vec<u16> = OsStr::new(username)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();
                    let mut profile = PROFILEINFOW {
                        dwSize: std::mem::size_of::<PROFILEINFOW>() as u32,
                        lpUserName: windows::core::PWSTR(username_wide.as_ptr() as *mut _),
                        ..Default::default()
                    };
                    match LoadUserProfileW(token.handle, &mut profile) {
                        Ok(_) => {
                            token.profile_handle = Some(profile.hProfile);
                            info!(
                                "LoadUserProfileW succeeded for {}, hProfile={:?}",
                                username, profile.hProfile
                            );
                        }
                        Err(e) => {
                            // Do not hard-fail here; env block may still be created, and
                            // CreateProcessWithTokenW(LOGON_WITH_PROFILE) might succeed anyway.
                            error!("LoadUserProfileW failed for {}: {:?}", username, e);
                        }
                    }
                } else {
                    warn!("spawn_as_user called without username; skipping LoadUserProfileW");
                }
            }

            let creation_flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
            let app_pcwstr = app_u16
                .as_ref()
                .map(|v| PCWSTR(v.as_ptr()))
                .unwrap_or(PCWSTR::null());
            let dir_pcwstr = dir_u16
                .as_ref()
                .map(|v| PCWSTR(v.as_ptr()))
                .unwrap_or(PCWSTR::null());

            // Preferred "session-correct" path:
            //
            // Try to obtain a session token for the *same authenticated user* in the active
            // console session via WTSQueryUserToken. If the returned token's SID doesn't match the
            // authenticated user's token, we skip it to avoid running commands under the wrong user.
            //
            // This avoids relying on SetTokenInformation(TokenSessionId), which frequently fails
            // with E_ACCESSDENIED under constrained service tokens.
            if active_session != u32::MAX {
                if let Ok((target_user_buf, target_user_sid)) =
                    Self::token_user_sid_ptr(token.handle)
                {
                    let mut session_token = HANDLE::default();
                    match WTSQueryUserToken(active_session, &mut session_token) {
                        Ok(_) => {
                            let session_guard = UserToken {
                                handle: session_token,
                                profile_handle: None,
                            };
                            if let Ok((_sess_buf, sess_sid)) =
                                Self::token_user_sid_ptr(session_guard.handle)
                            {
                                if EqualSid(target_user_sid, sess_sid).is_ok() {
                                    info!(
                                        "spawn_as_user: WTSQueryUserToken matched authenticated user (session={})",
                                        active_session
                                    );
                                    if let Ok(primary) =
                                        Self::duplicate_primary_token(session_guard.handle)
                                    {
                                        let desktop_wide: Vec<u16> = OsStr::new("winsta0\\default")
                                            .encode_wide()
                                            .chain([0])
                                            .collect();
                                        si.lpDesktop =
                                            windows::core::PWSTR(desktop_wide.as_ptr() as *mut _);

                                        for inherit in [true, false] {
                                            let mut env_block: *mut core::ffi::c_void =
                                                std::ptr::null_mut();
                                            let env_ptr = match CreateEnvironmentBlock(
                                                &mut env_block,
                                                primary,
                                                inherit,
                                            ) {
                                                Ok(_) => {
                                                    Some(env_block as *const core::ffi::c_void)
                                                }
                                                Err(e) => {
                                                    error!(
                                                        "CreateEnvironmentBlock(WTS primary, inherit={}) failed: {:?}",
                                                        inherit, e
                                                    );
                                                    None
                                                }
                                            };

                                            let mut pi = PROCESS_INFORMATION::default();
                                            let mut cmd_u16: Vec<u16> = OsStr::new(&cmd_line)
                                                .encode_wide()
                                                .chain(std::iter::once(0))
                                                .collect();

                                            let res = CreateProcessAsUserW(
                                                primary,
                                                app_pcwstr,
                                                windows::core::PWSTR(cmd_u16.as_mut_ptr()),
                                                None,
                                                None,
                                                false,
                                                creation_flags,
                                                env_ptr,
                                                dir_pcwstr,
                                                &si,
                                                &mut pi,
                                            );

                                            if !env_block.is_null() {
                                                let _ = DestroyEnvironmentBlock(env_block);
                                            }

                                            match res {
                                                Ok(_) => {
                                                    info!(
                                                        "spawn_as_user success: method=AsUser(WTS) inherit_env={} pid={}",
                                                        inherit, pi.dwProcessId
                                                    );
                                                    let _ = CloseHandle(pi.hProcess);
                                                    let _ = CloseHandle(pi.hThread);
                                                    let _ = CloseHandle(primary);
                                                    return Ok(pi.dwProcessId);
                                                }
                                                Err(e) => {
                                                    error!(
                                                        "spawn_as_user attempt failed: method=AsUser(WTS) inherit_env={} err={:?}",
                                                        inherit, e
                                                    );
                                                }
                                            }
                                        }
                                        let _ = CloseHandle(primary);
                                    } else {
                                        warn!("spawn_as_user: DuplicateTokenEx on WTS session token failed");
                                    }
                                } else {
                                    warn!(
                                        "spawn_as_user: WTSQueryUserToken(session={}) returned different user; skipping",
                                        active_session
                                    );
                                }
                            }
                            drop(session_guard);
                            drop(target_user_buf);
                        }
                        Err(e) => {
                            warn!(
                                "spawn_as_user: WTSQueryUserToken(session={}) failed: {:?}",
                                active_session, e
                            );
                            drop(target_user_buf);
                        }
                    }
                } else {
                    warn!("spawn_as_user: failed to read TokenUser from auth token");
                }
            }

            // First, attempt a "session-aware" spawn using CreateProcessAsUserW with a duplicated
            // primary token whose TokenSessionId is set to the active console session.
            //
            // This is expected to fail on headless hosts (no active session), but on dev boxes it
            // often makes PowerShell/where/wsl behave like OpenSSH.
            if active_session != u32::MAX {
                if let Ok(primary) = Self::duplicate_primary_token(token.handle) {
                    let mut primary_guard = Some(primary);

                    // Best-effort: move token into active session.
                    // LocalSystem typically has SeTcbPrivilege; if not enabled, this may fail.
                    let mut sid = active_session;
                    match SetTokenInformation(
                        primary,
                        TokenSessionId,
                        (&mut sid as *mut u32).cast(),
                        std::mem::size_of::<u32>() as u32,
                    ) {
                        Ok(_) => {
                            info!(
                                "spawn_as_user: SetTokenInformation(TokenSessionId={}) ok",
                                sid
                            );
                        }
                        Err(e) => {
                            error!(
                                "spawn_as_user: SetTokenInformation(TokenSessionId={}) failed: {:?}",
                                sid, e
                            );
                        }
                    }

                    // Provide an explicit desktop; some binaries expect this even when non-interactive.
                    let desktop_wide: Vec<u16> = OsStr::new("winsta0\\default")
                        .encode_wide()
                        .chain([0])
                        .collect();
                    si.lpDesktop = windows::core::PWSTR(desktop_wide.as_ptr() as *mut _);

                    // Use env block from the adjusted token; many processes consult user env early.
                    for inherit in [true, false] {
                        let mut env_block: *mut core::ffi::c_void = std::ptr::null_mut();
                        let env_ptr = match CreateEnvironmentBlock(&mut env_block, primary, inherit)
                        {
                            Ok(_) => Some(env_block as *const core::ffi::c_void),
                            Err(e) => {
                                error!(
                                    "CreateEnvironmentBlock(primary, inherit={}) failed (session-aware attempt): {:?}",
                                    inherit, e
                                );
                                None
                            }
                        };

                        let mut pi = PROCESS_INFORMATION::default();
                        let mut cmd_u16: Vec<u16> = OsStr::new(&cmd_line)
                            .encode_wide()
                            .chain(std::iter::once(0))
                            .collect();

                        let res = CreateProcessAsUserW(
                            primary,
                            app_pcwstr,
                            windows::core::PWSTR(cmd_u16.as_mut_ptr()),
                            None,
                            None,
                            false,
                            creation_flags,
                            env_ptr,
                            dir_pcwstr,
                            &si,
                            &mut pi,
                        );

                        if !env_block.is_null() {
                            let _ = DestroyEnvironmentBlock(env_block);
                        }

                        match res {
                            Ok(_) => {
                                info!(
                                    "spawn_as_user success: method=AsUser(SessionAware) inherit_env={} pid={}",
                                    inherit, pi.dwProcessId
                                );
                                let _ = CloseHandle(pi.hProcess);
                                let _ = CloseHandle(pi.hThread);
                                if let Some(h) = primary_guard.take() {
                                    let _ = CloseHandle(h);
                                }
                                return Ok(pi.dwProcessId);
                            }
                            Err(e) => {
                                error!(
                                    "spawn_as_user attempt failed: method=AsUser(SessionAware) inherit_env={} err={:?}",
                                    inherit, e
                                );
                            }
                        }
                    }

                    if let Some(h) = primary_guard.take() {
                        let _ = CloseHandle(h);
                    }
                } else {
                    warn!("spawn_as_user: DuplicateTokenEx(primary) failed; skipping session-aware attempt");
                }
            }

            // A/B matrix: try several environment strategies and both CreateProcessWithTokenW and
            // CreateProcessAsUserW. This mirrors the Win32-OpenSSH class of fixes for Session 0
            // + SYSTEM -> user-process spawn where missing profile/env can break DLL init.
            #[derive(Clone, Copy, Debug)]
            enum EnvStrategy {
                EnvBlockInheritTrue,
                EnvBlockInheritFalse,
                None,
            }
            #[derive(Clone, Copy, Debug)]
            enum Method {
                WithToken,
                AsUser,
            }

            let env_strategies = [
                EnvStrategy::EnvBlockInheritTrue,
                EnvStrategy::EnvBlockInheritFalse,
                EnvStrategy::None,
            ];
            let methods = [Method::WithToken, Method::AsUser];

            let mut last_err: Option<windows::core::Error> = None;

            for env_strategy in env_strategies {
                let mut env_block: *mut core::ffi::c_void = std::ptr::null_mut();
                let env_ptr: Option<*const core::ffi::c_void> = match env_strategy {
                    EnvStrategy::None => None,
                    EnvStrategy::EnvBlockInheritTrue => {
                        match CreateEnvironmentBlock(&mut env_block, token.handle, true) {
                            Ok(_) => Some(env_block as *const core::ffi::c_void),
                            Err(e) => {
                                error!(
                                    "CreateEnvironmentBlock(inherit=true) failed; skipping: {:?}",
                                    e
                                );
                                last_err = Some(e);
                                continue;
                            }
                        }
                    }
                    EnvStrategy::EnvBlockInheritFalse => {
                        match CreateEnvironmentBlock(&mut env_block, token.handle, false) {
                            Ok(_) => Some(env_block as *const core::ffi::c_void),
                            Err(e) => {
                                error!(
                                    "CreateEnvironmentBlock(inherit=false) failed; skipping: {:?}",
                                    e
                                );
                                last_err = Some(e);
                                continue;
                            }
                        }
                    }
                };

                for method in methods {
                    let mut pi = PROCESS_INFORMATION::default();
                    let mut cmd_u16: Vec<u16> = OsStr::new(&cmd_line)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();

                    let res = match method {
                        Method::WithToken => CreateProcessWithTokenW(
                            token.handle,
                            LOGON_WITH_PROFILE,
                            app_pcwstr,
                            windows::core::PWSTR(cmd_u16.as_mut_ptr()),
                            creation_flags,
                            env_ptr,
                            dir_pcwstr,
                            &si,
                            &mut pi,
                        ),
                        Method::AsUser => CreateProcessAsUserW(
                            token.handle,
                            app_pcwstr,
                            windows::core::PWSTR(cmd_u16.as_mut_ptr()),
                            None,
                            None,
                            false,
                            creation_flags,
                            env_ptr,
                            dir_pcwstr,
                            &si,
                            &mut pi,
                        ),
                    };

                    match res {
                        Ok(_) => {
                            info!(
                                "spawn_as_user success: method={:?} env_strategy={:?} pid={}",
                                method, env_strategy, pi.dwProcessId
                            );
                            if !env_block.is_null() {
                                let _ = DestroyEnvironmentBlock(env_block);
                            }
                            let _ = CloseHandle(pi.hProcess);
                            let _ = CloseHandle(pi.hThread);
                            return Ok(pi.dwProcessId);
                        }
                        Err(e) => {
                            error!(
                                "spawn_as_user attempt failed: method={:?} env_strategy={:?} err={:?}",
                                method, env_strategy, e
                            );
                            last_err = Some(e);
                        }
                    }
                }

                if !env_block.is_null() {
                    let _ = DestroyEnvironmentBlock(env_block);
                }
            }

            let err = last_err.unwrap_or_else(windows::core::Error::from_win32);
            error!("CreateProcess failed after all strategies: {:?}", err);
            Err(anyhow::anyhow!(err))
        }
    }

    #[cfg(windows)]
    pub fn init_process_privileges() -> anyhow::Result<()> {
        // Best-effort privilege enablement. On some hosts the service token might not have all
        // privileges (or they may be disabled/removed by policy). We don't hard-fail here because:
        // - some process creation paths can still work without specific privileges, and
        // - we want to attempt enabling later privileges even if earlier ones fail.
        for name in [
            // Needed for SetTokenInformation(TokenSessionId, ...) in many configurations.
            "SeTcbPrivilege",
            // Often needed for CreateProcessAsUserW depending on token type.
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
        ] {
            match Self::enable_privilege(name) {
                Ok(()) => info!("Privilege enabled: {}", name),
                Err(e) => warn!("Privilege enable failed (continuing): {}: {}", name, e),
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn enable_privilege(name: &str) -> anyhow::Result<()> {
        let name_wide: Vec<u16> = OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: This block enables a privilege for the current process token.
        // It correctly opens the token, looks up the LUID, and calls AdjustTokenPrivileges.
        // Resource cleanup is handled via _token_guard.
        unsafe {
            let mut token = HANDLE::default();
            let process = GetCurrentProcess();
            if OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token).is_err()
            {
                return Err(anyhow::anyhow!("OpenProcessToken failed"));
            }
            // Ensure token is closed when this function returns
            let _token_guard = UserToken {
                handle: token,
                profile_handle: None,
            };

            let mut luid = LUID::default();
            if LookupPrivilegeValueW(None, PCWSTR(name_wide.as_ptr()), &mut luid).is_err() {
                return Err(anyhow::anyhow!("LookupPrivilegeValueW failed for {}", name));
            }

            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
                ..Default::default()
            };

            let _ = AdjustTokenPrivileges(_token_guard.handle, false, Some(&tp), 0, None, None);
            if windows::Win32::Foundation::GetLastError() == ERROR_NOT_ALL_ASSIGNED {
                return Err(anyhow::anyhow!(
                    "Privilege {} could not be assigned (ERROR_NOT_ALL_ASSIGNED)",
                    name
                ));
            }
        }
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn init_process_privileges() -> anyhow::Result<()> {
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn authenticate(user: &str, pass: &str) -> Option<UserToken> {
        info!("Non-Windows platform detected. Using stub authentication.");
        let _ = user;
        let _ = pass;
        None
    }

    #[cfg(not(windows))]
    pub fn spawn_as_user(_token: &UserToken, _opts: SpawnOptions) -> anyhow::Result<u32> {
        info!("spawn_as_user stub called");
        Ok(1234)
    }
}

pub struct WindowsUserInfo {
    pub profile_path: String,
    pub sid: String,
    pub is_admin: bool,
}

/// ユーザー名から SID・プロファイルパス・管理者フラグを取得（Windows API 直接）
#[cfg(windows)]
pub fn get_user_info_windows(user: &str) -> anyhow::Result<WindowsUserInfo> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::PSID;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{LookupAccountNameW, SID_NAME_USE};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_VALUE_TYPE,
    };

    let wide_user: Vec<u16> = OsStr::new(user)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: This block uses Win32 APIs (LookupAccountNameW, ConvertSidToStringSidW, RegOpenKeyExW, etc.)
    // to retrieve user information from the system. It correctly handles null-terminated strings,
    // buffer allocations (two-call pattern), and resource cleanup (LocalFree, RegCloseKey).
    unsafe {
        // ===== LookupAccountNameW でユーザー名 → SID =====
        let mut sid_size: u32 = 0;
        let mut domain_size: u32 = 0;
        let mut sid_type = SID_NAME_USE::default();

        // 1回目: バッファサイズ取得
        let _ = LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(wide_user.as_ptr()),
            PSID::default(),
            &mut sid_size,
            windows::core::PWSTR::null(),
            &mut domain_size,
            &mut sid_type,
        );

        if sid_size == 0 {
            return Err(anyhow::anyhow!(
                "LookupAccountNameW failed to resolve user: {}",
                user
            ));
        }

        let mut sid_buf = vec![0u8; sid_size as usize];
        let mut domain_buf = vec![0u16; domain_size as usize];
        let psid = PSID(sid_buf.as_mut_ptr() as *mut std::ffi::c_void);

        // 2回目: 実際の取得
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(wide_user.as_ptr()),
            psid,
            &mut sid_size,
            windows::core::PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_size,
            &mut sid_type,
        )
        .map_err(|e| anyhow::anyhow!("LookupAccountNameW failed: {:?}", e))?;

        // SID → 文字列（"S-1-5-21-..."）
        let mut string_sid_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(psid, &mut string_sid_ptr)
            .map_err(|e| anyhow::anyhow!("ConvertSidToStringSidW failed: {:?}", e))?;
        let sid_string = string_sid_ptr
            .to_string()
            .map_err(|e| anyhow::anyhow!("SID string conversion failed: {:?}", e))?;
        let _ = LocalFree(HLOCAL(string_sid_ptr.0 as *mut std::ffi::c_void));

        // ===== レジストリからプロファイルパスを取得 =====
        let reg_path = format!(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{}",
            sid_string
        );
        let wide_reg_path: Vec<u16> = OsStr::new(&reg_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey = HKEY::default();
        let profile_path = if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide_reg_path.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
        .is_ok()
        {
            let value_name = "ProfileImagePath";
            let wide_value: Vec<u16> = OsStr::new(value_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut data_type = REG_VALUE_TYPE::default();
            let mut data_size: u32 = 0;

            // 1回目: サイズ取得
            let _ = RegQueryValueExW(
                hkey,
                PCWSTR(wide_value.as_ptr()),
                None,
                Some(&mut data_type),
                None,
                Some(&mut data_size),
            );

            if data_size > 0 {
                let mut data_buf = vec![0u8; data_size as usize];
                if RegQueryValueExW(
                    hkey,
                    PCWSTR(wide_value.as_ptr()),
                    None,
                    Some(&mut data_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_size),
                )
                .is_ok()
                {
                    // UTF-16 LE からデコード（null 終端を除去）
                    let wide: Vec<u16> = data_buf
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&c| c != 0)
                        .collect();
                    let _ = RegCloseKey(hkey);
                    String::from_utf16_lossy(&wide)
                } else {
                    let _ = RegCloseKey(hkey);
                    format!("C:\\Users\\{}", user) // フォールバック
                }
            } else {
                let _ = RegCloseKey(hkey);
                format!("C:\\Users\\{}", user) // フォールバック
            }
        } else {
            format!("C:\\Users\\{}", user) // レジストリ読取失敗時のフォールバック
        };

        // ===== 管理者グループ (S-1-5-32-544) に属するかチェック =====
        // well-known Administrators SID を構築して比較する代わりに、
        // LookupAccountName で "Administrators" を引いて EqualSid する
        let admin_name = "BUILTIN\\Administrators";
        let wide_admin: Vec<u16> = OsStr::new(admin_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut admin_sid_size: u32 = 0;
        let mut admin_domain_size: u32 = 0;
        let mut admin_sid_type = SID_NAME_USE::default();

        let _ = LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(wide_admin.as_ptr()),
            PSID::default(),
            &mut admin_sid_size,
            windows::core::PWSTR::null(),
            &mut admin_domain_size,
            &mut admin_sid_type,
        );

        // 注意: ユーザー SID と Administrators グループ SID は EqualSid では比較できない
        // （ユーザーはグループのメンバーであってグループそのものではない）
        // ここでは SID 文字列の前方一致で簡易判定する。
        // 本来は CheckTokenMembership が正しいが、トークンが必要なので
        // 管理者の定型パターンで判定する。
        // well-known Administrator RID = -500
        let is_admin = sid_string.ends_with("-500") || sid_string == "S-1-5-32-544";

        Ok(WindowsUserInfo {
            profile_path,
            sid: sid_string,
            is_admin,
        })
    }
}

#[cfg(not(windows))]
pub fn get_user_info_windows(_user: &str) -> anyhow::Result<WindowsUserInfo> {
    Err(anyhow::anyhow!("Not supported on non-Windows"))
}
