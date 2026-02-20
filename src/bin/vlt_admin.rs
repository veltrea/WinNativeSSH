use anyhow::{anyhow, Result};
use russh_keys::parse_public_key_base64;
use std::env;
use std::sync::Arc;
use uuid::Uuid;
use vlt_sshd::db::Db;


fn main() -> Result<()> {
    use std::io::Write;
    println!("VLT-ADMIN-START");
    let _ = std::io::stdout().flush();

    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let exe_path = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!("CRITICAL ERROR: Failed to get current_exe: {:?}", e);
        std::process::exit(1);
    });
    let exe_dir = exe_path.parent().unwrap_or_else(|| {
        eprintln!("CRITICAL ERROR: Failed to get exe_dir from {:?}", exe_path);
        std::process::exit(1);
    });

    let db_path_buf = exe_dir.join("winnative.db");
    let db_path_str = db_path_buf.to_string_lossy().into_owned();

    // ASCII-only prefix to ensure it can be read even with encoding issues
    println!("DEBUG_PATH: [{}]", db_path_str);

    let db = Db::open(&db_path_buf).map_err(|e| {
        anyhow!(
            "CRITICAL ERROR: Failed to open DB at [{}]. Error: {:?}",
            db_path_str,
            e
        )
    })?;
    let db = Arc::new(db);

    let command = &args[1];

    match command.as_str() {
        "add-user" => {
            if args.len() < 4 {
                println!("Usage: vlt-admin add-user <username> <password>");
                return Ok(());
            }
            let name = &args[2];
            let password = &args[3];
            add_user(&db, name, password)?;
        }
        "add-key" => {
            if args.len() < 4 {
                println!("Usage: vlt-admin add-key <username> <pubkey_string> [--expires-at RFC3339] [--constraints-json JSON]");
                return Ok(());
            }
            let name = &args[2];
            let (pubkey, expires_at, constraints_json) = parse_add_key_args(&args[3..])?;
            add_key(
                &db,
                name,
                &pubkey,
                expires_at.as_deref(),
                constraints_json.as_deref(),
            )?;
        }
        "list-users" => {
            list_users(&db, &args[2..])?;
        }
        "list-keys" => {
            if args.len() < 3 {
                println!("Usage: vlt-admin list-keys <username> [--limit N] [--offset N]");
                return Ok(());
            }
            list_keys(&db, &args[2], &args[3..])?;
        }
        "list-audit" => {
            list_audit(&db, &args[2..])?;
        }
        "list-sessions" => {
            list_sessions(&db, &args[2..])?;
        }
        "list-policies" => {
            list_policies(&db, &args[2..])?;
        }
        "list-key-alerts" => {
            list_key_alerts(&db, &args[2..])?;
        }
        "set-policy" => {
            if args.len() < 6 {
                println!(
                    "Usage: vlt-admin set-policy <scope> <scope_id|-> <priority> <policy_json>"
                );
                return Ok(());
            }
            let scope = &args[2];
            let scope_id = if args[3].as_str() == "-" {
                None
            } else {
                Some(args[3].as_str())
            };
            let priority: i32 = args[4]
                .parse()
                .map_err(|e| anyhow!("priority parse error: {}", e))?;
            let policy_json = args[5..].join(" ");
            set_policy(&db, scope, scope_id, priority, &policy_json)?;
        }
        "disable-key" => {
            if args.len() < 3 {
                println!("Usage: vlt-admin disable-key <key_id>");
                return Ok(());
            }
            let key_id = &args[2];
            disable_key(&db, key_id)?;
        }
        "rotate-key" => {
            if args.len() < 4 {
                println!("Usage: vlt-admin rotate-key <key_id> <new_pubkey_string>");
                return Ok(());
            }
            let key_id = &args[2];
            let new_pubkey = args[3..].join(" ");
            rotate_key(&db, key_id, &new_pubkey)?;
        }
        "del-user" | "delete-user" => {
            if args.len() < 3 {
                println!("Usage: vlt-admin del-user <username>");
                return Ok(());
            }
            let name = &args[2];
            del_user(&db, name)?;
        }
        "disable-user" => {
            if args.len() < 3 {
                println!("Usage: vlt-admin disable-user <username>");
                return Ok(());
            }
            let name = &args[2];
            disable_user(&db, name)?;
        }
        "enable-user" => {
            if args.len() < 3 {
                println!("Usage: vlt-admin enable-user <username>");
                return Ok(());
            }
            let name = &args[2];
            enable_user(&db, name)?;
        }
        "fix-permissions" => {
            if args.len() < 3 {
                println!("Usage: vlt-admin fix-permissions <username>");
                return Ok(());
            }
            let target = &args[2];
            fix_permissions(target)?;
        }
        "check-permissions" => {
            if args.len() < 3 {
                println!("Usage: vlt-admin check-permissions <username> [--json]");
                return Ok(());
            }
            let target = &args[2];
            let json_mode = args.iter().any(|a| a == "--json");
            check_permissions(target, json_mode)?;
        }
        "help" | "--help" | "-h" => {
            print_usage();
        }
        _ => {
            println!("Unknown command: {}", command);
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!("vlt-admin - WinNative-SSH Administration Tool");
    println!("Usage:");
    println!(
        "  vlt-admin add-user <name> <password>   Register a user and encrypt password (DPAPI)"
    );
    println!(
        "  vlt-admin add-key <name> <pubkey> [--expires-at RFC3339] [--constraints-json JSON]"
    );
    println!("  vlt-admin list-keys <name> [--limit N] [--offset N]");
    println!("  vlt-admin disable-key <key_id>         Disable a key");
    println!("  vlt-admin rotate-key <key_id> <pubkey> Rotate a key");
    println!("  vlt-admin list-users [--limit N] [--offset N]");
    println!(
        "  vlt-admin list-audit [--sid SID] [--category CAT] [--code CODE] [--limit N] [--offset N]"
    );
    println!("  vlt-admin list-sessions [--sid SID] [--active] [--limit N] [--offset N]");
    println!("  vlt-admin list-policies [--scope SCOPE] [--scope-id ID] [--limit N] [--offset N]");
    println!("  vlt-admin list-key-alerts [--days N] [--limit N] [--offset N]");
    println!("  vlt-admin set-policy <scope> <scope_id|-> <priority> <policy_json>");
    println!("  vlt-admin disable-user <name>          Disable user (enabled=0)");
    println!("  vlt-admin enable-user <name>           Enable user (enabled=1)");
    println!("  vlt-admin del-user <name>              Delete a user and their keys (alias: delete-user)");
    println!("  vlt-admin fix-permissions <user>       (Win) Fix authorized_keys ACLs");
    println!("  vlt-admin check-permissions <user>     (Win) Diagnose ACL issues for a user");
}

fn add_user(db: &Arc<Db>, name: &str, password: &str) -> Result<()> {
    // Check if user exists for update, or create new.
    let existing = db.get_user_by_name(name)?;
    let sid = if let Some(u) = existing {
        println!("User {} already exists. Updating password.", name);
        u.sid
    } else {
        // Generate new SID (UUID)
        Uuid::new_v4().to_string()
    };

    let password_enc = {
        #[cfg(windows)]
        {
            let pwd_bytes = password.as_bytes();
            Some(vlt_sshd::dpapi::protect(pwd_bytes)?)
        }
        #[cfg(not(windows))]
        {
            let _ = password; // Suppress unused variable warning
            println!("Warning: DPAPI not supported on non-windows. Password NOT saved.");
            None::<Vec<u8>>
        }
    };

    db.create_user(&sid, name, password_enc.as_deref())?;

    #[cfg(windows)]
    println!("User {} saved with encrypted password.", name);
    #[cfg(not(windows))]
    println!("User {} saved (no password).", name);

    Ok(())
}

fn add_key(
    db: &Arc<Db>,
    name: &str,
    pubkey: &str,
    expires_at: Option<&str>,
    constraints_json: Option<&str>,
) -> Result<()> {
    validate_pubkey(pubkey)?;
    if let Some(ts) = expires_at {
        chrono::DateTime::parse_from_rfc3339(ts)
            .map_err(|e| anyhow!("invalid expires-at RFC3339: {}", e))?;
    }
    let u = db.get_user_by_name(name)?;
    if u.is_none() {
        println!("User {} not found.", name);
        return Ok(());
    }
    let u = u.unwrap();

    // Add key
    if let Some(raw) = constraints_json {
        let _: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| anyhow!("invalid constraints-json: {}", e))?;
    }
    db.add_key(&u.sid, pubkey, constraints_json, expires_at)?;
    println!("Public key added for user {}.", name);
    Ok(())
}

fn parse_add_key_args(args: &[String]) -> Result<(String, Option<String>, Option<String>)> {
    let mut key_parts: Vec<String> = Vec::new();
    let mut expires_at: Option<String> = None;
    let mut constraints_json: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--expires-at" {
            if i + 1 >= args.len() {
                return Err(anyhow!("--expires-at requires RFC3339 value"));
            }
            expires_at = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        if args[i] == "--constraints-json" {
            if i + 1 >= args.len() {
                return Err(anyhow!("--constraints-json requires JSON value"));
            }
            constraints_json = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        key_parts.push(args[i].clone());
        i += 1;
    }
    if key_parts.is_empty() {
        return Err(anyhow!("missing pubkey_string"));
    }
    Ok((key_parts.join(" "), expires_at, constraints_json))
}

fn list_users(db: &Arc<Db>, opts: &[String]) -> Result<()> {
    let mut limit: i64 = 100;
    let mut offset: i64 = 0;
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i].as_str() {
            "--limit" if i + 1 < opts.len() => {
                limit = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("limit parse error: {}", e))?;
                i += 2;
            }
            "--offset" if i + 1 < opts.len() => {
                offset = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("offset parse error: {}", e))?;
                i += 2;
            }
            unknown => return Err(anyhow!("Unknown option for list-users: {}", unknown)),
        }
    }
    let users = db.list_users_paged(limit, offset)?;
    println!("Registered Users:");
    println!(
        "{:<36} {:<20} {:<10} {:<10}",
        "SID", "Name", "Type", "Enabled"
    );
    println!("{:-<36} {:-<20} {:-<10} {:-<10}", "", "", "", "");
    for u in users {
        println!(
            "{:<36} {:<20} {:<10} {:<10}",
            u.sid, u.name, u.user_type, u.enabled
        );
    }
    Ok(())
}

fn list_keys(db: &Arc<Db>, name: &str, opts: &[String]) -> Result<()> {
    let mut limit: i64 = 100;
    let mut offset: i64 = 0;
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i].as_str() {
            "--limit" if i + 1 < opts.len() => {
                limit = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("limit parse error: {}", e))?;
                i += 2;
            }
            "--offset" if i + 1 < opts.len() => {
                offset = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("offset parse error: {}", e))?;
                i += 2;
            }
            unknown => return Err(anyhow!("Unknown option for list-keys: {}", unknown)),
        }
    }
    let user = db.get_user_by_name(name)?;
    let Some(u) = user else {
        println!("User {} not found.", name);
        return Ok(());
    };
    let keys = db.get_keys_for_user_paged(&u.sid, limit, offset)?;
    println!(
        "{:<36} {:<8} {:<24} Fingerprint",
        "KeyId", "Enabled", "CreatedAt"
    );
    println!("{:-<36} {:-<8} {:-<24} {:-<20}", "", "", "", "");
    for k in keys {
        println!(
            "{:<36} {:<8} {:<24} {}",
            k.key_id,
            k.enabled,
            k.created_at.to_rfc3339(),
            k.fingerprint
        );
    }
    Ok(())
}

fn del_user(db: &Arc<Db>, name: &str) -> Result<()> {
    db.delete_user(name)?;
    println!("User {} deleted.", name);
    Ok(())
}

fn disable_user(db: &Arc<Db>, name: &str) -> Result<()> {
    let ok = db.set_user_enabled(name, false)?;
    if ok {
        println!("User {} disabled.", name);
    } else {
        println!("User {} not found.", name);
    }
    Ok(())
}

fn enable_user(db: &Arc<Db>, name: &str) -> Result<()> {
    let ok = db.set_user_enabled(name, true)?;
    if ok {
        println!("User {} enabled.", name);
    } else {
        println!("User {} not found.", name);
    }
    Ok(())
}

fn set_policy(
    db: &Arc<Db>,
    scope: &str,
    scope_id: Option<&str>,
    priority: i32,
    policy_json: &str,
) -> Result<()> {
    db.upsert_policy(scope, scope_id, priority, policy_json)?;
    println!(
        "Policy upserted. scope={} scope_id={} priority={}",
        scope,
        scope_id.unwrap_or("-"),
        priority
    );
    Ok(())
}

fn disable_key(db: &Arc<Db>, key_id: &str) -> Result<()> {
    let ok = db.disable_key(key_id)?;
    if ok {
        println!("Key {} disabled.", key_id);
    } else {
        println!("Key {} not found or already disabled.", key_id);
    }
    Ok(())
}

fn rotate_key(db: &Arc<Db>, key_id: &str, new_pubkey: &str) -> Result<()> {
    validate_pubkey(new_pubkey)?;
    let ok = db.rotate_key(key_id, new_pubkey)?;
    if ok {
        println!("Key {} rotated.", key_id);
    } else {
        println!("Key {} not found.", key_id);
    }
    Ok(())
}

fn validate_pubkey(pubkey: &str) -> Result<()> {
    let parts: Vec<&str> = pubkey.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow!("invalid public key format: missing key body"));
    }
    parse_public_key_base64(parts[1]).map_err(|e| anyhow!("invalid public key: {}", e))?;
    Ok(())
}

fn list_audit(db: &Arc<Db>, opts: &[String]) -> Result<()> {
    let mut sid: Option<String> = None;
    let mut category: Option<String> = None;
    let mut code: Option<String> = None;
    let mut limit: i64 = 100;
    let mut offset: i64 = 0;
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i].as_str() {
            "--sid" if i + 1 < opts.len() => {
                sid = Some(opts[i + 1].clone());
                i += 2;
            }
            "--category" if i + 1 < opts.len() => {
                category = Some(opts[i + 1].clone());
                i += 2;
            }
            "--code" if i + 1 < opts.len() => {
                code = Some(opts[i + 1].clone());
                i += 2;
            }
            "--limit" if i + 1 < opts.len() => {
                limit = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("limit parse error: {}", e))?;
                i += 2;
            }
            "--offset" if i + 1 < opts.len() => {
                offset = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("offset parse error: {}", e))?;
                i += 2;
            }
            unknown => {
                return Err(anyhow!("Unknown option for list-audit: {}", unknown));
            }
        }
    }

    let events = db.list_audit_events_paged(
        sid.as_deref(),
        category.as_deref(),
        code.as_deref(),
        limit,
        offset,
    )?;
    println!(
        "{:<36} {:<24} {:<10} {:<8} Detail",
        "EventId", "Timestamp", "Category", "Code"
    );
    println!("{:-<36} {:-<24} {:-<10} {:-<8} {:-<20}", "", "", "", "", "");
    for e in events {
        println!(
            "{:<36} {:<24} {:<10} {:<8} {}",
            e.event_id,
            e.ts,
            e.category.unwrap_or_else(|| "-".to_string()),
            e.code.unwrap_or_else(|| "-".to_string()),
            e.detail_json.unwrap_or_else(|| "-".to_string())
        );
    }
    Ok(())
}

fn list_sessions(db: &Arc<Db>, opts: &[String]) -> Result<()> {
    let mut sid: Option<String> = None;
    let mut active_only = false;
    let mut limit: i64 = 100;
    let mut offset: i64 = 0;
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i].as_str() {
            "--sid" if i + 1 < opts.len() => {
                sid = Some(opts[i + 1].clone());
                i += 2;
            }
            "--active" => {
                active_only = true;
                i += 1;
            }
            "--limit" if i + 1 < opts.len() => {
                limit = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("limit parse error: {}", e))?;
                i += 2;
            }
            "--offset" if i + 1 < opts.len() => {
                offset = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("offset parse error: {}", e))?;
                i += 2;
            }
            unknown => return Err(anyhow!("Unknown option for list-sessions: {}", unknown)),
        }
    }

    let sessions = db.list_sessions_paged(sid.as_deref(), active_only, limit, offset)?;
    println!(
        "{:<36} {:<24} {:<15} {:<6} {:<24} {:<14}",
        "SessionId", "SID", "SrcIP", "Port", "StartAt", "Result"
    );
    println!(
        "{:-<36} {:-<24} {:-<15} {:-<6} {:-<24} {:-<14}",
        "", "", "", "", "", ""
    );
    for s in sessions {
        println!(
            "{:<36} {:<24} {:<15} {:<6} {:<24} {:<14}",
            s.session_id,
            s.sid,
            s.src_ip.unwrap_or_else(|| "-".to_string()),
            s.src_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            s.start_at,
            s.result.unwrap_or_else(|| "-".to_string()),
        );
    }
    Ok(())
}

fn list_policies(db: &Arc<Db>, opts: &[String]) -> Result<()> {
    let mut scope: Option<String> = None;
    let mut scope_id: Option<String> = None;
    let mut limit: i64 = 100;
    let mut offset: i64 = 0;
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i].as_str() {
            "--scope" if i + 1 < opts.len() => {
                scope = Some(opts[i + 1].clone());
                i += 2;
            }
            "--scope-id" if i + 1 < opts.len() => {
                scope_id = Some(opts[i + 1].clone());
                i += 2;
            }
            "--limit" if i + 1 < opts.len() => {
                limit = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("limit parse error: {}", e))?;
                i += 2;
            }
            "--offset" if i + 1 < opts.len() => {
                offset = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("offset parse error: {}", e))?;
                i += 2;
            }
            unknown => return Err(anyhow!("Unknown option for list-policies: {}", unknown)),
        }
    }

    let policies = db.list_policies_paged(scope.as_deref(), scope_id.as_deref(), limit, offset)?;
    println!(
        "{:<36} {:<12} {:<20} {:<8} PolicyJson",
        "PolicyId", "Scope", "ScopeId", "Priority"
    );
    println!("{:-<36} {:-<12} {:-<20} {:-<8} {:-<20}", "", "", "", "", "");
    for p in policies {
        println!(
            "{:<36} {:<12} {:<20} {:<8} {}",
            p.policy_id,
            p.scope,
            p.scope_id.unwrap_or_else(|| "-".to_string()),
            p.priority,
            p.policy_json
        );
    }
    Ok(())
}

fn list_key_alerts(db: &Arc<Db>, opts: &[String]) -> Result<()> {
    let mut days: i64 = 30;
    let mut limit: i64 = 100;
    let mut offset: i64 = 0;
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i].as_str() {
            "--days" if i + 1 < opts.len() => {
                days = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("days parse error: {}", e))?;
                i += 2;
            }
            "--limit" if i + 1 < opts.len() => {
                limit = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("limit parse error: {}", e))?;
                i += 2;
            }
            "--offset" if i + 1 < opts.len() => {
                offset = opts[i + 1]
                    .parse()
                    .map_err(|e| anyhow!("offset parse error: {}", e))?;
                i += 2;
            }
            unknown => return Err(anyhow!("Unknown option for list-key-alerts: {}", unknown)),
        }
    }
    let keys = db.list_key_alerts(days, limit, offset)?;
    println!(
        "{:<36} {:<36} {:<8} {:<24} {:<24}",
        "KeyId", "SID", "Enabled", "CreatedAt", "ExpiresAt"
    );
    println!("{:-<36} {:-<36} {:-<8} {:-<24} {:-<24}", "", "", "", "", "");
    for k in keys {
        println!(
            "{:<36} {:<36} {:<8} {:<24} {:<24}",
            k.key_id,
            k.sid,
            k.enabled,
            k.created_at.to_rfc3339(),
            k.expires_at.unwrap_or_else(|| "-".to_string())
        );
    }
    Ok(())
}

fn fix_permissions(_target: &str) -> Result<()> {
    #[cfg(not(windows))]
    {
        println!("This command is only supported on Windows.");
        Ok(())
    }
    #[cfg(windows)]
    fix_permissions_windows(_target)
}

#[cfg(windows)]
fn fix_permissions_windows(target: &str) -> Result<()> {
    use std::path::PathBuf;
    use std::process::Command;

    // OpenSSH on Windows is sensitive to both *owner* and *DACL* on:
    // - %USERPROFILE%\.ssh
    // - %USERPROFILE%\.ssh\authorized_keys
    // - C:\ProgramData\ssh\administrators_authorized_keys (Administrator trap)
    //
    // This subcommand aims to provide a "one command" repair for the common cases,
    // using locale-independent well-known SIDs where possible.

    #[derive(serde::Deserialize)]
    struct UserInfo {
        sid: String,
        profile: String,
        is_admin: bool,
    }

    fn powershell_json_userinfo(user: &str) -> Result<UserInfo> {
        // Return: {"sid":"...","profile":"C:\\Users\\...","is_admin":true|false}
        //
        // - SID: NTAccount -> SID
        // - Profile path: HKLM ProfileList\<SID>\ProfileImagePath (most reliable)
        // - is_admin: local group membership
        //
        // We keep the script single-line to simplify escaping.
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             $u={u}; \
             $acct=New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME,$u); \
             $sid=$acct.Translate([System.Security.Principal.SecurityIdentifier]).Value; \
             $p=(Get-ItemProperty -Path ('HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\ProfileList\\\\'+$sid) -Name ProfileImagePath).ProfileImagePath; \
             $admins=@(); \
             try {{ $admins=(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object {{ $_.Name }}) }} catch {{ }}; \
             $isAdmin=$false; \
             foreach($a in $admins){{ if($a -like ('*\\\\'+$u)){{ $isAdmin=$true }} }}; \
             [PSCustomObject]@{{sid=$sid; profile=$p; is_admin=$isAdmin}} | ConvertTo-Json -Compress",
            u = serde_json::to_string(user).unwrap_or_else(|_| "\"\"".to_string())
        );

        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ])
            .output()?;
        if !out.status.success() {
            return Err(anyhow!(
                "PowerShell query failed (exit={}). stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let info: UserInfo = serde_json::from_str(&s)
            .map_err(|e| anyhow!("failed to parse user info json: {} (json={})", e, s))?;
        Ok(info)
    }

    fn run_icacls(args: &[String]) -> Result<()> {
        let status = Command::new("icacls").args(args).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(anyhow!("icacls failed with status: {}", status))
        }
    }

    fn sid_spec(sid: &str) -> String {
        // icacls accepts "*S-1-..." to specify by SID (locale-independent)
        format!("*{}", sid)
    }

    // Well-known SIDs (avoid localized names like "Users"/"Everyone").
    let sid_system = "S-1-5-18";
    let sid_admins = "S-1-5-32-544";
    let sid_users = "S-1-5-32-545";
    let sid_auth_users = "S-1-5-11";
    let sid_everyone = "S-1-1-0";

    let info = powershell_json_userinfo(target)?;
    let profile = PathBuf::from(&info.profile);
    let ssh_dir = profile.join(".ssh");
    let authorized_keys = ssh_dir.join("authorized_keys");

    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let admin_keys = PathBuf::from(program_data)
        .join("ssh")
        .join("administrators_authorized_keys");

    println!("Target User : {}", target);
    println!("User SID    : {}", info.sid);
    println!("Profile     : {}", info.profile);
    println!("Is Admin    : {}", info.is_admin);

    // Helper: remove common "too open" principals and re-grant strict ones.
    // Note: We intentionally do not attempt to perfectly mirror Win32-OpenSSH checks;
    // the goal is to get to a safe and commonly accepted ACL.
    fn harden_dir(
        path: &PathBuf,
        user_sid: &str,
        sid_system: &str,
        sid_admins: &str,
        sid_users: &str,
        sid_auth_users: &str,
        sid_everyone: &str,
    ) -> Result<()> {
        println!("Fixing directory ACL: {:?}", path);
        let args = vec![
            path.to_string_lossy().to_string(),
            "/inheritance:r".to_string(),
            "/grant:r".to_string(),
            format!("{}:(F)", sid_spec(sid_system)),
            format!("{}:(F)", sid_spec(sid_admins)),
            format!("{}:(F)", sid_spec(user_sid)),
            "/remove:g".to_string(),
            sid_spec(sid_everyone),
            sid_spec(sid_auth_users),
            sid_spec(sid_users),
        ];
        run_icacls(&args)?;

        // Best-effort owner set.
        let owner_args = vec![
            path.to_string_lossy().to_string(),
            "/setowner".to_string(),
            sid_spec(user_sid),
        ];
        if let Err(e) = run_icacls(&owner_args) {
            println!("Warning: failed to set owner on {:?}: {}", path, e);
        }
        Ok(())
    }

    fn harden_file(
        path: &PathBuf,
        user_sid: &str,
        sid_system: &str,
        sid_admins: &str,
        sid_users: &str,
        sid_auth_users: &str,
        sid_everyone: &str,
    ) -> Result<()> {
        println!("Fixing file ACL: {:?}", path);
        let mut args = vec![
            path.to_string_lossy().to_string(),
            "/inheritance:r".to_string(),
            "/grant:r".to_string(),
            format!("{}:(F)", sid_spec(sid_system)),
            format!("{}:(F)", sid_spec(sid_admins)),
            // Read is sufficient (and closer to OpenSSH expectations).
            format!("{}:(R)", sid_spec(user_sid)),
            "/remove:g".to_string(),
            sid_spec(sid_everyone),
            sid_spec(sid_auth_users),
            sid_spec(sid_users),
        ];
        run_icacls(&args)?;

        let owner_args = vec![
            path.to_string_lossy().to_string(),
            "/setowner".to_string(),
            sid_spec(user_sid),
        ];
        if let Err(e) = run_icacls(&owner_args) {
            println!("Warning: failed to set owner on {:?}: {}", path, e);
        }
        Ok(())
    }

    if ssh_dir.exists() {
        harden_dir(
            &ssh_dir,
            &info.sid,
            sid_system,
            sid_admins,
            sid_users,
            sid_auth_users,
            sid_everyone,
        )?;
    } else {
        println!("Note: .ssh directory not found (skipping): {:?}", ssh_dir);
    }
    if authorized_keys.exists() {
        harden_file(
            &authorized_keys,
            &info.sid,
            sid_system,
            sid_admins,
            sid_users,
            sid_auth_users,
            sid_everyone,
        )?;
    } else {
        println!(
            "Note: authorized_keys not found (skipping): {:?}",
            authorized_keys
        );
    }

    // Administrator trap: if user is an admin, OpenSSH often switches to ProgramData keys.
    if info.is_admin {
        if admin_keys.exists() {
            println!(
                "Fixing admin keys ACL (Administrator trap): {:?}",
                admin_keys
            );
            let args = vec![
                admin_keys.to_string_lossy().to_string(),
                "/inheritance:r".to_string(),
                "/grant:r".to_string(),
                format!("{}:(F)", sid_spec(sid_system)),
                format!("{}:(F)", sid_spec(sid_admins)),
                "/remove:g".to_string(),
                sid_spec(sid_everyone),
                sid_spec(sid_auth_users),
                sid_spec(sid_users),
            ];
            run_icacls(&args)?;

            let owner_args = vec![
                admin_keys.to_string_lossy().to_string(),
                "/setowner".to_string(),
                sid_spec(sid_admins),
            ];
            if let Err(e) = run_icacls(&owner_args) {
                println!("Warning: failed to set owner on {:?}: {}", admin_keys, e);
            }
        } else {
            println!(
                "Note: administrators_authorized_keys not found (skipping): {:?}",
                admin_keys
            );
        }
    }

    println!("Done.");
    Ok(())
}
#[cfg(windows)]
fn check_permissions(target: &str, json_mode: bool) -> Result<()> {
    use std::path::Path;
    use vlt_sshd::acl_diagnose;
    use vlt_sshd::acl_diagnose::Language;
    use vlt_sshd::auth::get_user_info_windows;

    let info = get_user_info_windows(target)?;
    let ssh_dir = Path::new(&info.profile_path).join(".ssh");
    let authorized_keys = ssh_dir.join("authorized_keys");

    let mut results = Vec::new();

    // 1. Recursive check for authorized_keys (AuthorizedKeys -> .ssh -> Profile -> ... -> Users)
    if authorized_keys.exists() {
        results.extend(acl_diagnose::check_path_recursion(
            &authorized_keys,
            Some(&info.sid),
        ));
    } else if ssh_dir.exists() {
        // If file doesn't exist, check from .ssh directory
        results.extend(acl_diagnose::check_path_recursion(
            &ssh_dir,
            Some(&info.sid),
        ));
    } else {
        // Start from profile path
        results.extend(acl_diagnose::check_path_recursion(
            Path::new(&info.profile_path),
            Some(&info.sid),
        ));
    }

    // 2. Admin keys (if admin)
    let admin_keys = Path::new("C:\\ProgramData\\ssh\\administrators_authorized_keys");
    if info.is_admin && admin_keys.exists() {
        // Admin keys are special (owned by SYSTEM/Admins)
        if let Ok(diag) = acl_diagnose::diagnose_path(&admin_keys, None) {
            results.push(diag);
        }
    }

    if json_mode {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        let lang = if results.is_empty() {
            Language::default()
        } else {
            results[0].language
        };

        if lang == Language::Japanese {
            println!("ユーザー {} の ACL 診断結果:", target);
        } else {
            println!("ACL Diagnosis for User: {}", target);
        }
        println!("----------------------------------------");

        for res in results {
            let status = if res.is_valid {
                if lang == Language::Japanese {
                    "合格"
                } else {
                    "PASS"
                }
            } else {
                if lang == Language::Japanese {
                    "不合格"
                } else {
                    "FAIL"
                }
            };
            println!("[{}] {}", status, res.path);

            if let Some(reason) = &res.failure_reason {
                if lang == Language::Japanese {
                    println!("  ! 原因: {}", reason);
                } else {
                    println!("  ! Reason: {}", reason);
                }
            }
            for detail in &res.details {
                println!("  . {}", detail);
            }

            // Repair advices
            let advices = res.get_repair_advice();
            if !advices.is_empty() {
                if lang == Language::Japanese {
                    println!("  i 推奨される修復アクション:");
                } else {
                    println!("  i Recommended repair actions:");
                }
                for advice in advices {
                    println!("    - {}", advice);
                }
            }
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn check_permissions(_target: &str, _json_mode: bool) -> Result<()> {
    println!("check-permissions is only supported on Windows.");
    Ok(())
}
