#[cfg(windows)]
use crate::eventlog;
use base64::Engine;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub sid: String,
    pub name: String,
    pub user_type: String,
    pub enabled: bool,
    pub password_enc: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SshKey {
    pub key_id: String,
    pub sid: String,
    pub pubkey: String,
    pub fingerprint: String,
    pub enabled: bool,
    pub constraints_json: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub session_id: Option<String>,
    pub sid: Option<String>,
    pub ts: String,
    pub category: Option<String>,
    pub code: Option<String>,
    pub detail_json: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub sid: String,
    pub src_ip: Option<String>,
    pub src_port: Option<i64>,
    pub start_at: String,
    pub end_at: Option<String>,
    pub result: Option<String>,
    pub worker_pid: Option<u32>,
    pub pipe_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub policy_id: String,
    pub scope: String,
    pub scope_id: Option<String>,
    pub priority: i32,
    pub policy_json: String,
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                sid TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            )",
            [],
        )?;

        // Simple migration: Try to add password_enc column.
        if let Err(e) = conn.execute("ALTER TABLE users ADD COLUMN password_enc BLOB", []) {
            let msg = e.to_string();
            if !msg.contains("duplicate column name") {
                log::warn!("Migration failed (password_enc): {:?}", e);
            }
        }

        conn.execute(
            "CREATE TABLE IF NOT EXISTS keys (
                key_id TEXT PRIMARY KEY,
                sid TEXT NOT NULL,
                pubkey TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                constraints_json TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY (sid) REFERENCES users(sid)
            )",
            [],
        )?;
        if let Err(e) = conn.execute("ALTER TABLE keys ADD COLUMN expires_at TEXT", []) {
            let msg = e.to_string();
            if !msg.contains("duplicate column name") {
                log::warn!("Migration failed (keys.expires_at): {:?}", e);
            }
        }

        conn.execute(
            "CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                scope_id TEXT,
                priority INTEGER NOT NULL,
                policy_json TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                sid TEXT NOT NULL,
                src_ip TEXT,
                src_port INTEGER,
                start_at TEXT NOT NULL,
                end_at TEXT,
                result TEXT,
                worker_pid INTEGER,
                pipe_name TEXT
            )",
            [],
        )?;

        // Migrations
        if let Err(e) = conn.execute("ALTER TABLE sessions ADD COLUMN worker_pid INTEGER", []) {
            let msg = e.to_string();
            if !msg.contains("duplicate column name") {
                log::warn!("Migration failed (sessions.worker_pid): {:?}", e);
            }
        }
        if let Err(e) = conn.execute("ALTER TABLE sessions ADD COLUMN pipe_name TEXT", []) {
            let msg = e.to_string();
            if !msg.contains("duplicate column name") {
                log::warn!("Migration failed (sessions.pipe_name): {:?}", e);
            }
        }

        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                session_id TEXT,
                sid TEXT,
                ts TEXT NOT NULL,
                category TEXT,
                code TEXT,
                detail_json TEXT
            )",
            [],
        )?;

        // Indices
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_sid ON audit_events(sid)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_sid ON sessions(sid)",
            [],
        )?;

        Ok(())
    }

    pub fn get_user_by_name(&self, name: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT sid, name, type, enabled, password_enc FROM users WHERE name = ?")?;
        let mut rows = stmt.query(params![name])?;

        if let Some(row) = rows.next()? {
            Ok(Some(User {
                sid: row.get(0)?,
                name: row.get(1)?,
                user_type: row.get(2)?,
                enabled: row.get::<_, i32>(3)? != 0,
                password_enc: row.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn set_user_password_enc(&self, sid: &str, password_enc: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE users SET password_enc = ? WHERE sid = ?",
            params![password_enc, sid],
        )?;
        Ok(())
    }

    pub fn get_keys_for_user(&self, sid: &str) -> Result<Vec<SshKey>> {
        self.get_keys_for_user_paged(sid, i64::MAX, 0)
    }

    pub fn get_keys_for_user_paged(
        &self,
        sid: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SshKey>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key_id, sid, pubkey, fingerprint, enabled, constraints_json, created_at, expires_at
             FROM keys
             WHERE sid = ?
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?",
        )?;
        let rows = stmt.query_map(params![sid, limit, offset], |row| {
            let created_at_str: String = row.get(6)?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .unwrap_or_default()
                .with_timezone(&Utc);
            Ok(SshKey {
                key_id: row.get(0)?,
                sid: row.get(1)?,
                pubkey: row.get(2)?,
                fingerprint: row.get(3)?,
                enabled: row.get::<_, i32>(4)? != 0,
                constraints_json: row.get(5)?,
                created_at,
                expires_at: row.get(7)?,
            })
        })?;

        let mut keys = Vec::new();
        for key in rows {
            keys.push(key?);
        }
        Ok(keys)
    }

    pub fn create_user(&self, sid: &str, name: &str, password_enc: Option<&[u8]>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO users (sid, name, type, enabled, password_enc) VALUES (?, ?, 'User', 1, ?)",
            params![sid, name, password_enc],
        )?;
        Ok(())
    }

    pub fn add_key(
        &self,
        sid: &str,
        pubkey: &str,
        constraints: Option<&str>,
        expires_at: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let key_id = uuid::Uuid::new_v4().to_string();
        let fingerprint = compute_pubkey_fingerprint(pubkey);
        let ts = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO keys (key_id, sid, pubkey, fingerprint, enabled, constraints_json, created_at, expires_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
            params![key_id, sid, pubkey, &fingerprint, constraints, ts, expires_at],
        )?;
        let audit_id = uuid::Uuid::new_v4().to_string();
        let detail_json = format!(
            r#"{{"action":"key_added","sid":"{}","key_id":"{}","fingerprint":"{}"}}"#,
            sid, key_id, fingerprint
        );
        conn.execute(
            "INSERT INTO audit_events (event_id, session_id, sid, ts, category, code, detail_json) VALUES (?, NULL, ?, ?, 'key', '1500', ?)",
            params![audit_id, sid, ts, detail_json],
        )?;
        Ok(())
    }

    pub fn disable_key(&self, key_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let key_meta: Result<(String, String)> = conn.query_row(
            "SELECT sid, fingerprint FROM keys WHERE key_id = ?",
            params![key_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        if let Ok((sid, fingerprint)) = key_meta {
            let updated = conn.execute(
                "UPDATE keys SET enabled = 0 WHERE key_id = ?",
                params![key_id],
            )?;
            if updated > 0 {
                let audit_id = uuid::Uuid::new_v4().to_string();
                let ts = Utc::now().to_rfc3339();
                let detail_json = format!(
                    r#"{{"action":"key_disabled","sid":"{}","key_id":"{}","fingerprint":"{}"}}"#,
                    sid, key_id, fingerprint
                );
                conn.execute(
                    "INSERT INTO audit_events (event_id, session_id, sid, ts, category, code, detail_json) VALUES (?, NULL, ?, ?, 'key', '1500', ?)",
                    params![audit_id, sid, ts, detail_json],
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn rotate_key(&self, key_id: &str, new_pubkey: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let key_meta: Result<(String, String)> = conn.query_row(
            "SELECT sid, fingerprint FROM keys WHERE key_id = ?",
            params![key_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        if let Ok((sid, old_fingerprint)) = key_meta {
            let new_fingerprint = compute_pubkey_fingerprint(new_pubkey);
            let ts = Utc::now().to_rfc3339();
            let updated = conn.execute(
                "UPDATE keys SET pubkey = ?, fingerprint = ?, enabled = 1, created_at = ?, expires_at = NULL WHERE key_id = ?",
                params![new_pubkey, &new_fingerprint, ts, key_id],
            )?;
            if updated > 0 {
                let audit_id = uuid::Uuid::new_v4().to_string();
                let detail_json = format!(
                    r#"{{"action":"key_rotated","sid":"{}","key_id":"{}","old_fingerprint":"{}","new_fingerprint":"{}"}}"#,
                    sid, key_id, old_fingerprint, new_fingerprint
                );
                conn.execute(
                    "INSERT INTO audit_events (event_id, session_id, sid, ts, category, code, detail_json) VALUES (?, NULL, ?, ?, 'key', '1500', ?)",
                    params![audit_id, sid, ts, detail_json],
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn list_key_alerts(&self, days: i64, limit: i64, offset: i64) -> Result<Vec<SshKey>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key_id, sid, pubkey, fingerprint, enabled, constraints_json, created_at, expires_at
             FROM keys
             WHERE enabled = 1
               AND expires_at IS NOT NULL
               AND datetime(expires_at) <= datetime('now', '+' || ? || ' day')
             ORDER BY datetime(expires_at) ASC
             LIMIT ? OFFSET ?",
        )?;
        let rows = stmt.query_map(params![days, limit, offset], |row| {
            let created_at_str: String = row.get(6)?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .unwrap_or_default()
                .with_timezone(&Utc);
            Ok(SshKey {
                key_id: row.get(0)?,
                sid: row.get(1)?,
                pubkey: row.get(2)?,
                fingerprint: row.get(3)?,
                enabled: row.get::<_, i32>(4)? != 0,
                constraints_json: row.get(5)?,
                created_at,
                expires_at: row.get(7)?,
            })
        })?;
        let mut keys = Vec::new();
        for key in rows {
            keys.push(key?);
        }
        Ok(keys)
    }

    pub fn list_users(&self) -> Result<Vec<User>> {
        self.list_users_paged(i64::MAX, 0)
    }

    pub fn list_users_paged(&self, limit: i64, offset: i64) -> Result<Vec<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT sid, name, type, enabled, password_enc
             FROM users
             ORDER BY name ASC
             LIMIT ? OFFSET ?",
        )?;
        let rows = stmt.query_map(params![limit, offset], |row| {
            Ok(User {
                sid: row.get(0)?,
                name: row.get(1)?,
                user_type: row.get(2)?,
                enabled: row.get::<_, i32>(3)? != 0,
                password_enc: row.get(4)?,
            })
        })?;

        let mut users = Vec::new();
        for user in rows {
            users.push(user?);
        }
        Ok(users)
    }

    pub fn delete_user(&self, name: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let sid_result: Result<String> = conn.query_row(
            "SELECT sid FROM users WHERE name = ?",
            params![name],
            |row| row.get(0),
        );

        if let Ok(sid) = sid_result {
            conn.execute("DELETE FROM keys WHERE sid = ?", params![&sid])?;
            conn.execute("DELETE FROM users WHERE sid = ?", params![&sid])?;
            let audit_id = uuid::Uuid::new_v4().to_string();
            let ts = Utc::now().to_rfc3339();
            let detail_json = format!(
                r#"{{"action":"keys_revoked_by_user_delete","user":"{}"}}"#,
                name
            );
            conn.execute(
                "INSERT INTO audit_events (event_id, session_id, sid, ts, category, code, detail_json) VALUES (?, NULL, ?, ?, 'key', '1500', ?)",
                params![audit_id, &sid, ts, detail_json],
            )?;
        }
        Ok(())
    }

    pub fn disable_user(&self, name: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let sid_result: Result<String> = conn.query_row(
            "SELECT sid FROM users WHERE name = ?",
            params![name],
            |row| row.get(0),
        );
        if let Ok(sid) = sid_result {
            let updated =
                conn.execute("UPDATE users SET enabled = 0 WHERE sid = ?", params![&sid])?;
            if updated > 0 {
                let event_id = uuid::Uuid::new_v4().to_string();
                let ts = Utc::now().to_rfc3339();
                let detail = format!(
                    r#"{{"action":"user_disabled","user":"{}","sid":"{}"}}"#,
                    name, sid
                );
                conn.execute(
                    "INSERT INTO audit_events (event_id, session_id, sid, ts, category, code, detail_json) VALUES (?, NULL, ?, ?, 'user', '1600', ?)",
                    params![event_id, &sid, ts, detail],
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn set_user_enabled(&self, name: &str, enabled: bool) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let sid_result: Result<String> = conn.query_row(
            "SELECT sid FROM users WHERE name = ?",
            params![name],
            |row| row.get(0),
        );
        if let Ok(sid) = sid_result {
            let updated = conn.execute(
                "UPDATE users SET enabled = ? WHERE sid = ?",
                params![if enabled { 1 } else { 0 }, &sid],
            )?;
            if updated > 0 {
                let event_id = uuid::Uuid::new_v4().to_string();
                let ts = Utc::now().to_rfc3339();
                let action = if enabled {
                    "user_enabled"
                } else {
                    "user_disabled"
                };
                let detail = format!(
                    r#"{{"action":"{}","user":"{}","sid":"{}"}}"#,
                    action, name, sid
                );
                conn.execute(
                    "INSERT INTO audit_events (event_id, session_id, sid, ts, category, code, detail_json) VALUES (?, NULL, ?, ?, 'user', '1600', ?)",
                    params![event_id, &sid, ts, detail],
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn add_audit_event(
        &self,
        session_id: Option<&str>,
        sid: Option<&str>,
        category: &str,
        code: &str,
        detail_json: &str,
    ) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let ts = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_events (event_id, session_id, sid, ts, category, code, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![id, session_id, sid, ts, category, code, detail_json],
        )?;
        #[cfg(windows)]
        eventlog::write_event(category, code, detail_json);
        Ok(())
    }

    pub fn upsert_policy(
        &self,
        scope: &str,
        scope_id: Option<&str>,
        priority: i32,
        policy_json: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let ts = Utc::now().to_rfc3339();
        let policy_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO policies (policy_id, scope, scope_id, priority, policy_json) VALUES (?, ?, ?, ?, ?)",
            params![policy_id, scope, scope_id, priority, policy_json],
        )?;
        let event_id = uuid::Uuid::new_v4().to_string();
        let detail = format!(
            r#"{{"action":"policy_changed","scope":"{}","scope_id":"{}","priority":{},"policy_id":"{}"}}"#,
            scope,
            scope_id.unwrap_or(""),
            priority,
            policy_id
        );
        conn.execute(
            "INSERT INTO audit_events (event_id, session_id, sid, ts, category, code, detail_json) VALUES (?, NULL, NULL, ?, 'policy', '1400', ?)",
            params![event_id, ts, detail],
        )?;
        Ok(())
    }

    pub fn start_session(
        &self,
        session_id: &str,
        sid: Option<&str>,
        src_ip: Option<&str>,
        src_port: Option<i64>,
        worker_pid: Option<u32>,
        pipe_name: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let ts = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO sessions (session_id, sid, src_ip, src_port, start_at, end_at, result, worker_pid, pipe_name) 
             VALUES (?, COALESCE(?, ''), ?, ?, ?, NULL, NULL, ?, ?)",
            params![session_id, sid, src_ip, src_port, ts, worker_pid, pipe_name],
        )?;
        Ok(())
    }

    pub fn end_session(&self, session_id: &str, result: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let ts = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE sessions SET end_at = ?, result = ? WHERE session_id = ?",
            params![ts, result, session_id],
        )?;
        Ok(())
    }

    pub fn list_audit_events(
        &self,
        sid: Option<&str>,
        category: Option<&str>,
        code: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AuditEvent>> {
        self.list_audit_events_paged(sid, category, code, limit, 0)
    }

    pub fn list_audit_events_paged(
        &self,
        sid: Option<&str>,
        category: Option<&str>,
        code: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_id, session_id, sid, ts, category, code, detail_json
             FROM audit_events
             WHERE (?1 IS NULL OR sid = ?1)
               AND (?2 IS NULL OR category = ?2)
               AND (?3 IS NULL OR code = ?3)
             ORDER BY ts DESC
             LIMIT ?4 OFFSET ?5",
        )?;
        let rows = stmt.query_map(params![sid, category, code, limit, offset], |row| {
            Ok(AuditEvent {
                event_id: row.get(0)?,
                session_id: row.get(1)?,
                sid: row.get(2)?,
                ts: row.get(3)?,
                category: row.get(4)?,
                code: row.get(5)?,
                detail_json: row.get(6)?,
            })
        })?;

        let mut events = Vec::new();
        for e in rows {
            events.push(e?);
        }
        Ok(events)
    }

    pub fn list_sessions(
        &self,
        sid: Option<&str>,
        active_only: bool,
        limit: i64,
    ) -> Result<Vec<SessionRecord>> {
        self.list_sessions_paged(sid, active_only, limit, 0)
    }

    pub fn list_sessions_paged(
        &self,
        sid: Option<&str>,
        active_only: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SessionRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session_id, sid, src_ip, src_port, start_at, end_at, result, worker_pid, pipe_name
             FROM sessions
             WHERE (?1 IS NULL OR sid = ?1)
               AND (?2 = 0 OR end_at IS NULL)
             ORDER BY start_at DESC
             LIMIT ?3 OFFSET ?4",
        )?;
        let rows = stmt.query_map(
            params![sid, if active_only { 1 } else { 0 }, limit, offset],
            |row| {
                Ok(SessionRecord {
                    session_id: row.get(0)?,
                    sid: row.get(1)?,
                    src_ip: row.get(2)?,
                    src_port: row.get(3)?,
                    start_at: row.get(4)?,
                    end_at: row.get(5)?,
                    result: row.get(6)?,
                    worker_pid: row.get(7)?,
                    pipe_name: row.get(8)?,
                })
            },
        )?;

        let mut sessions = Vec::new();
        for s in rows {
            sessions.push(s?);
        }
        Ok(sessions)
    }

    pub fn list_policies(
        &self,
        scope: Option<&str>,
        scope_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<PolicyRecord>> {
        self.list_policies_paged(scope, scope_id, limit, 0)
    }

    pub fn list_policies_paged(
        &self,
        scope: Option<&str>,
        scope_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PolicyRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT policy_id, scope, scope_id, priority, policy_json
             FROM policies
             WHERE (?1 IS NULL OR scope = ?1)
               AND (?2 IS NULL OR scope_id = ?2)
             ORDER BY priority DESC
             LIMIT ?3 OFFSET ?4",
        )?;
        let rows = stmt.query_map(params![scope, scope_id, limit, offset], |row| {
            Ok(PolicyRecord {
                policy_id: row.get(0)?,
                scope: row.get(1)?,
                scope_id: row.get(2)?,
                priority: row.get(3)?,
                policy_json: row.get(4)?,
            })
        })?;

        let mut policies = Vec::new();
        for p in rows {
            policies.push(p?);
        }
        Ok(policies)
    }

    pub fn get_effective_policy(&self, sid: &str) -> Result<crate::protocol::Policy> {
        let conn = self.conn.lock().unwrap();
        // Search user-specific first, then global, ordered by priority
        let mut stmt = conn.prepare(
            "SELECT policy_json FROM policies
             WHERE (scope = 'user' AND scope_id = ?1)
                OR (scope = 'global' AND scope_id IS NULL)
             ORDER BY CASE WHEN scope = 'user' THEN 0 ELSE 1 END, priority DESC
             LIMIT 1",
        )?;
        let policy_json: Option<String> = stmt
            .query_row(params![sid], |row| row.get(0))
            .optional()?;

        if let Some(json) = policy_json {
            if let Ok(policy) = serde_json::from_str(&json) {
                return Ok(policy);
            }
        }

        // Default fallback policy
        Ok(crate::protocol::Policy {
            allow_exec: true,
            allow_port_forwarding: false,
            terminal_encoding: "utf-8".to_string(),
            idle_timeout_seconds: 3600,
        })
    }
}

fn compute_pubkey_fingerprint(pubkey: &str) -> String {
    let key_body = pubkey.split_whitespace().nth(1).unwrap_or(pubkey);
    let decoded = base64::engine::general_purpose::STANDARD.decode(key_body);
    let payload = decoded.unwrap_or_else(|_| pubkey.as_bytes().to_vec());
    let digest = Sha256::digest(payload);
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{}", encoded)
}
