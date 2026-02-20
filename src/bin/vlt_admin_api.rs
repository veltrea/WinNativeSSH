use anyhow::{anyhow, Result};
use chrono::Utc;
use russh_keys::parse_public_key_base64;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use uuid::Uuid;
use vlt_sshd::db::Db;
#[cfg(windows)]
use vlt_sshd::dpapi;

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query: Option<String>,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct SetPolicyReq {
    scope: String,
    scope_id: Option<String>,
    priority: i32,
    policy_json: String,
}

#[derive(Debug, Deserialize)]
struct DisableKeyReq {
    key_id: String,
}

#[derive(Debug, Deserialize)]
struct RotateKeyReq {
    key_id: String,
    new_pubkey: String,
}

#[derive(Debug, Deserialize)]
struct AddKeyReq {
    user: String,
    pubkey: String,
    constraints: Option<String>,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeyConstraints {
    comment: Option<String>,
    use_case: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct DisableUserReq {
    user: String,
}

#[derive(Debug, Deserialize)]
struct EnableUserReq {
    user: String,
}

#[derive(Debug, Deserialize)]
struct DeleteUserReq {
    user: String,
}

#[derive(Debug, Deserialize)]
struct AddUserReq {
    user: String,
    password: Option<String>,
}

fn main() -> Result<()> {
    env_logger::init();
    let listener = TcpListener::bind("127.0.0.1:9443")?;
    let db = Arc::new(Db::open("winnative.db")?);
    let admin_token = std::env::var("WNSSH_ADMIN_TOKEN").ok();
    if admin_token.is_none() {
        log::warn!(
            "WNSSH_ADMIN_TOKEN is not set; non-health API calls will return service_misconfigured"
        );
    }
    log::info!("WinNative Admin API listening on http://127.0.0.1:9443");

    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                if let Err(e) = handle_client(&mut s, &db, admin_token.as_deref()) {
                    log::error!("admin api request failed: {:?}", e);
                    let _ = write_json(
                        &mut s,
                        500,
                        &json!({"ok": false, "error": format!("{}", e)}).to_string(),
                    );
                }
            }
            Err(e) => {
                log::error!("incoming connection failed: {:?}", e);
            }
        }
    }

    Ok(())
}

fn handle_client(stream: &mut TcpStream, db: &Arc<Db>, admin_token: Option<&str>) -> Result<()> {
    let req = read_request(stream)?;
    let request_id = Uuid::new_v4().to_string();
    if req.path != "/health" && req.path != "/ui" {
        if admin_token.is_none() {
            return write_api_error(
                stream,
                503,
                "service_misconfigured",
                "WNSSH_ADMIN_TOKEN is required",
                &request_id,
            );
        }
        if !is_authorized(&req, admin_token) {
            return write_api_error(
                stream,
                401,
                "unauthorized",
                "invalid or missing token",
                &request_id,
            );
        }
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/ui") => write_html(stream, 200, ADMIN_UI_HTML),
        ("GET", "/health") => write_json(
            stream,
            200,
            &json!({
                "ok": true,
                "service": "vlt_admin_api",
                "version": env!("CARGO_PKG_VERSION"),
                "timestamp": Utc::now().to_rfc3339(),
                "request_id": &request_id,
            })
            .to_string(),
        ),
        ("GET", "/feature-status") => write_json(
            stream,
            200,
            &json!({
                "ok": true,
                "features": {
                    "eventlog": "implemented",
                    "etw_export": "planned",
                    "siem_export": "planned",
                    "pq_hybrid_kex": "planned",
                    "ha_shared_store": "planned",
                    "fips_mode": "planned"
                },
                "request_id": &request_id
            })
            .to_string(),
        ),
        ("GET", "/audit") => {
            let query = req.query.unwrap_or_default();
            let params = parse_query(&query);
            let sid = opt_nonempty(&params, "sid");
            let category = opt_nonempty(&params, "category");
            let code = opt_nonempty(&params, "code");
            if let Some(sid) = sid {
                if let Err(msg) = validate_sid(sid) {
                    return write_api_error(stream, 400, "invalid_sid", &msg, &request_id);
                }
            }
            if let Some(category) = category {
                if let Err(msg) = validate_simple_token("category", category, 32) {
                    return write_api_error(stream, 400, "invalid_category", &msg, &request_id);
                }
            }
            if let Some(code) = code {
                if let Err(msg) = validate_event_code(code) {
                    return write_api_error(stream, 400, "invalid_code", &msg, &request_id);
                }
            }
            let limit = parse_limit(&params, 100, 1000);
            let offset = parse_offset(&params);
            let events = db.list_audit_events_paged(sid, category, code, limit, offset)?;
            let count = events.len() as i64;
            let has_more = count == limit;
            let next_offset = if has_more { Some(offset + count) } else { None };
            write_json(
                stream,
                200,
                &json!({
                    "ok": true,
                    "events": events,
                    "offset": offset,
                    "limit": limit,
                    "has_more": has_more,
                    "next_offset": next_offset,
                    "request_id": &request_id
                })
                .to_string(),
            )
        }
        ("GET", "/sessions") => {
            let query = req.query.unwrap_or_default();
            let params = parse_query(&query);
            let sid = opt_nonempty(&params, "sid");
            if let Some(sid) = sid {
                if let Err(msg) = validate_sid(sid) {
                    return write_api_error(stream, 400, "invalid_sid", &msg, &request_id);
                }
            }
            let active_only = params
                .get("active")
                .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
            let limit = parse_limit(&params, 100, 1000);
            let offset = parse_offset(&params);
            let sessions = db.list_sessions_paged(sid, active_only, limit, offset)?;
            let count = sessions.len() as i64;
            let has_more = count == limit;
            let next_offset = if has_more { Some(offset + count) } else { None };
            write_json(
                stream,
                200,
                &json!({
                    "ok": true,
                    "sessions": sessions,
                    "offset": offset,
                    "limit": limit,
                    "has_more": has_more,
                    "next_offset": next_offset,
                    "request_id": &request_id
                })
                .to_string(),
            )
        }
        ("GET", "/keys") => {
            let query = req.query.unwrap_or_default();
            let params = parse_query(&query);
            let user = opt_nonempty(&params, "user");
            let limit = parse_limit(&params, 100, 1000);
            let offset = parse_offset(&params);
            let Some(user_name) = user else {
                return write_api_error(
                    stream,
                    400,
                    "invalid_request",
                    "missing user query parameter",
                    &request_id,
                );
            };
            if let Err(msg) = validate_user_name(user_name) {
                return write_api_error(stream, 400, "invalid_user", &msg, &request_id);
            }
            let db_user = db.get_user_by_name(user_name)?;
            let Some(u) = db_user else {
                return write_api_error(
                    stream,
                    404,
                    "user_not_found",
                    "user does not exist",
                    &request_id,
                );
            };
            let keys = db.get_keys_for_user_paged(&u.sid, limit, offset)?;
            let count = keys.len() as i64;
            let has_more = count == limit;
            let next_offset = if has_more { Some(offset + count) } else { None };
            write_json(
                stream,
                200,
                &json!({
                    "ok": true,
                    "keys": keys,
                    "offset": offset,
                    "limit": limit,
                    "has_more": has_more,
                    "next_offset": next_offset,
                    "request_id": &request_id
                })
                .to_string(),
            )
        }
        ("GET", "/users") => {
            let query = req.query.unwrap_or_default();
            let params = parse_query(&query);
            let limit = parse_limit(&params, 100, 1000);
            let offset = parse_offset(&params);
            let users = db.list_users_paged(limit, offset)?;
            let count = users.len() as i64;
            let has_more = count == limit;
            let next_offset = if has_more { Some(offset + count) } else { None };
            write_json(
                stream,
                200,
                &json!({
                    "ok": true,
                    "users": users,
                    "offset": offset,
                    "limit": limit,
                    "has_more": has_more,
                    "next_offset": next_offset,
                    "request_id": &request_id
                })
                .to_string(),
            )
        }
        ("GET", "/policies") => {
            let query = req.query.unwrap_or_default();
            let params = parse_query(&query);
            let scope = opt_nonempty(&params, "scope");
            let scope_id = opt_nonempty(&params, "scope_id");
            if let Some(scope) = scope {
                if let Err(msg) = validate_scope(scope) {
                    return write_api_error(stream, 400, "invalid_scope", &msg, &request_id);
                }
            }
            if let Some(scope_id) = scope_id {
                if let Err(msg) = validate_scope_id(scope_id) {
                    return write_api_error(stream, 400, "invalid_scope_id", &msg, &request_id);
                }
            }
            let limit = parse_limit(&params, 100, 1000);
            let offset = parse_offset(&params);
            let policies = db.list_policies_paged(scope, scope_id, limit, offset)?;
            let count = policies.len() as i64;
            let has_more = count == limit;
            let next_offset = if has_more { Some(offset + count) } else { None };
            write_json(
                stream,
                200,
                &json!({
                    "ok": true,
                    "policies": policies,
                    "offset": offset,
                    "limit": limit,
                    "has_more": has_more,
                    "next_offset": next_offset,
                    "request_id": &request_id
                })
                .to_string(),
            )
        }
        ("GET", "/key-alerts") => {
            let query = req.query.unwrap_or_default();
            let params = parse_query(&query);
            let days = params
                .get("days")
                .and_then(|s| s.parse::<i64>().ok())
                .filter(|v| *v >= 0 && *v <= 3650)
                .unwrap_or(30);
            let limit = parse_limit(&params, 100, 1000);
            let offset = parse_offset(&params);
            let keys = db.list_key_alerts(days, limit, offset)?;
            let count = keys.len() as i64;
            let has_more = count == limit;
            let next_offset = if has_more { Some(offset + count) } else { None };
            write_json(
                stream,
                200,
                &json!({
                    "ok": true,
                    "keys": keys,
                    "days": days,
                    "offset": offset,
                    "limit": limit,
                    "has_more": has_more,
                    "next_offset": next_offset,
                    "request_id": &request_id
                })
                .to_string(),
            )
        }
        ("GET", "/acl/check") => {
            let query = req.query.unwrap_or_default();
            let params = parse_query(&query);
            let Some(user_name) = params.get("user") else {
                return write_api_error(
                    stream,
                    400,
                    "invalid_request",
                    "missing user query parameter",
                    &request_id,
                );
            };
            if let Err(msg) = validate_user_name(user_name) {
                return write_api_error(stream, 400, "invalid_user", &msg, &request_id);
            }

            match check_user_acls_api(user_name) {
                Ok(results) => write_json(
                    stream,
                    200,
                    &json!({
                        "ok": true,
                        "user": user_name,
                        "results": results,
                        "request_id": &request_id
                    })
                    .to_string(),
                ),
                Err(e) => write_api_error(
                    stream,
                    500,
                    "acl_check_failed",
                    &format!("{}", e),
                    &request_id,
                ),
            }
        }
        ("GET", "/acl") => {
            let query = req.query.unwrap_or_default();
            let params = parse_query(&query);
            let Some(path) = params.get("path") else {
                return write_api_error(
                    stream,
                    400,
                    "invalid_request",
                    "missing path query parameter",
                    &request_id,
                );
            };
            if let Err(msg) = validate_acl_path(path) {
                return write_api_error(stream, 400, "invalid_path", &msg, &request_id);
            }
            let mode = params.get("mode").map(String::as_str).unwrap_or("detailed");
            if mode != "detailed" && mode != "simple" {
                return write_api_error(
                    stream,
                    400,
                    "invalid_mode",
                    "mode must be detailed or simple",
                    &request_id,
                );
            }
            match query_acl(path, mode) {
                Ok(acl) => write_json(
                    stream,
                    200,
                    &json!({
                        "ok": true,
                        "path": path,
                        "acl": acl,
                        "request_id": &request_id
                    })
                    .to_string(),
                ),
                Err(e) => write_api_error(
                    stream,
                    500,
                    "acl_query_failed",
                    &format!("{}", e),
                    &request_id,
                ),
            }
        }
        ("POST", "/set-policy") => {
            let body: SetPolicyReq = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    return write_api_error(
                        stream,
                        400,
                        "invalid_json",
                        &format!("invalid_json: {}", e),
                        &request_id,
                    );
                }
            };
            if let Err(msg) = validate_scope(&body.scope) {
                return write_api_error(stream, 400, "invalid_scope", &msg, &request_id);
            }
            if let Some(scope_id) = body.scope_id.as_deref() {
                if let Err(msg) = validate_scope_id(scope_id) {
                    return write_api_error(stream, 400, "invalid_scope_id", &msg, &request_id);
                }
            }
            if !(-1000..=1000).contains(&body.priority) {
                return write_api_error(
                    stream,
                    400,
                    "invalid_priority",
                    "priority must be within -1000..1000",
                    &request_id,
                );
            }
            db.upsert_policy(
                &body.scope,
                body.scope_id.as_deref(),
                body.priority,
                &body.policy_json,
            )?;
            write_json(
                stream,
                200,
                &json!({"ok": true, "request_id": &request_id}).to_string(),
            )
        }
        ("POST", "/add-user") => {
            let body: AddUserReq = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    return write_api_error(
                        stream,
                        400,
                        "invalid_json",
                        &format!("invalid_json: {}", e),
                        &request_id,
                    );
                }
            };
            if let Err(msg) = validate_user_name(&body.user) {
                return write_api_error(stream, 400, "invalid_user", &msg, &request_id);
            }
            let existing = db.get_user_by_name(&body.user)?;
            let sid = existing
                .map(|u| u.sid)
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            let password_enc: Option<Vec<u8>> = match body.password {
                #[cfg(windows)]
                Some(p) => Some(dpapi::protect(p.as_bytes())?),
                #[cfg(not(windows))]
                Some(_) => None,
                None => None,
            };
            db.create_user(&sid, &body.user, password_enc.as_deref())?;
            write_json(
                stream,
                200,
                &json!({"ok": true, "sid": sid, "request_id": &request_id}).to_string(),
            )
        }
        ("POST", "/disable-key") => {
            let body: DisableKeyReq = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    return write_api_error(
                        stream,
                        400,
                        "invalid_json",
                        &format!("invalid_json: {}", e),
                        &request_id,
                    );
                }
            };
            if let Err(msg) = validate_key_id(&body.key_id) {
                return write_api_error(stream, 400, "invalid_key_id", &msg, &request_id);
            }
            let updated = db.disable_key(&body.key_id)?;
            write_json(
                stream,
                200,
                &json!({"ok": true, "updated": updated, "request_id": &request_id}).to_string(),
            )
        }
        ("POST", "/add-key") => {
            let body: AddKeyReq = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    return write_api_error(
                        stream,
                        400,
                        "invalid_json",
                        &format!("invalid_json: {}", e),
                        &request_id,
                    );
                }
            };
            if let Err(msg) = validate_user_name(&body.user) {
                return write_api_error(stream, 400, "invalid_user", &msg, &request_id);
            }
            let u = db.get_user_by_name(&body.user)?;
            let Some(user) = u else {
                return write_api_error(
                    stream,
                    404,
                    "user_not_found",
                    "user does not exist",
                    &request_id,
                );
            };
            if let Err(e) = validate_pubkey(&body.pubkey) {
                return write_api_error(
                    stream,
                    400,
                    "invalid_pubkey",
                    &format!("invalid_pubkey: {}", e),
                    &request_id,
                );
            }
            if let Some(expires_at) = body.expires_at.as_deref() {
                if chrono::DateTime::parse_from_rfc3339(expires_at).is_err() {
                    return write_api_error(
                        stream,
                        400,
                        "invalid_expires_at",
                        "expires_at must be RFC3339",
                        &request_id,
                    );
                }
            }
            let constraints = match body.constraints.as_deref() {
                Some(raw) => match normalize_constraints_json(raw) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        return write_api_error(stream, 400, "invalid_constraints", &e, &request_id)
                    }
                },
                None => None,
            };
            db.add_key(
                &user.sid,
                &body.pubkey,
                constraints.as_deref(),
                body.expires_at.as_deref(),
            )?;
            write_json(
                stream,
                200,
                &json!({"ok": true, "request_id": &request_id}).to_string(),
            )
        }
        ("POST", "/rotate-key") => {
            let body: RotateKeyReq = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    return write_api_error(
                        stream,
                        400,
                        "invalid_json",
                        &format!("invalid_json: {}", e),
                        &request_id,
                    );
                }
            };
            if let Err(msg) = validate_key_id(&body.key_id) {
                return write_api_error(stream, 400, "invalid_key_id", &msg, &request_id);
            }
            if let Err(e) = validate_pubkey(&body.new_pubkey) {
                return write_api_error(
                    stream,
                    400,
                    "invalid_pubkey",
                    &format!("invalid_pubkey: {}", e),
                    &request_id,
                );
            }
            let updated = db.rotate_key(&body.key_id, &body.new_pubkey)?;
            write_json(
                stream,
                200,
                &json!({"ok": true, "updated": updated, "request_id": &request_id}).to_string(),
            )
        }
        ("POST", "/disable-user") => {
            let body: DisableUserReq = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    return write_api_error(
                        stream,
                        400,
                        "invalid_json",
                        &format!("invalid_json: {}", e),
                        &request_id,
                    );
                }
            };
            if let Err(msg) = validate_user_name(&body.user) {
                return write_api_error(stream, 400, "invalid_user", &msg, &request_id);
            }
            let updated = db.set_user_enabled(&body.user, false)?;
            write_json(
                stream,
                200,
                &json!({"ok": true, "updated": updated, "request_id": &request_id}).to_string(),
            )
        }
        ("POST", "/enable-user") => {
            let body: EnableUserReq = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    return write_api_error(
                        stream,
                        400,
                        "invalid_json",
                        &format!("invalid_json: {}", e),
                        &request_id,
                    );
                }
            };
            if let Err(msg) = validate_user_name(&body.user) {
                return write_api_error(stream, 400, "invalid_user", &msg, &request_id);
            }
            let updated = db.set_user_enabled(&body.user, true)?;
            write_json(
                stream,
                200,
                &json!({"ok": true, "updated": updated, "request_id": &request_id}).to_string(),
            )
        }
        ("POST", "/delete-user") => {
            let body: DeleteUserReq = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    return write_api_error(
                        stream,
                        400,
                        "invalid_json",
                        &format!("invalid_json: {}", e),
                        &request_id,
                    );
                }
            };
            if let Err(msg) = validate_user_name(&body.user) {
                return write_api_error(stream, 400, "invalid_user", &msg, &request_id);
            }
            db.delete_user(&body.user)?;
            write_json(
                stream,
                200,
                &json!({"ok": true, "request_id": &request_id}).to_string(),
            )
        }
        _ => write_api_error(stream, 404, "not_found", "endpoint not found", &request_id),
    }
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Err(anyhow!("empty request"));
    }
    buf.truncate(n);

    let header_end = find_header_end(&buf).ok_or_else(|| anyhow!("invalid http request"))?;
    let header = &buf[..header_end];
    let mut body = buf[header_end + 4..].to_vec();

    let header_str = String::from_utf8_lossy(header);
    let mut lines = header_str.lines();
    let start = lines
        .next()
        .ok_or_else(|| anyhow!("missing request line"))?;
    let mut parts = start.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("missing method"))?
        .to_string();
    let raw_path = parts
        .next()
        .ok_or_else(|| anyhow!("missing path"))?
        .to_string();
    let (path, query) = if let Some((p, q)) = raw_path.split_once('?') {
        (p.to_string(), Some(q.to_string()))
    } else {
        (raw_path, None)
    };

    let mut headers = std::collections::HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    if body.len() < content_len {
        let mut remain = vec![0u8; content_len - body.len()];
        stream.read_exact(&mut remain)?;
        body.extend_from_slice(&remain);
    }

    if body.len() > content_len {
        body.truncate(content_len);
    }

    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_json(stream: &mut TcpStream, status: u16, body: &str) -> Result<()> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        503 => "Service Unavailable",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn write_html(stream: &mut TcpStream, status: u16, body: &str) -> Result<()> {
    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn write_api_error(
    stream: &mut TcpStream,
    status: u16,
    code: &str,
    message: &str,
    request_id: &str,
) -> Result<()> {
    write_json(
        stream,
        status,
        &json!({
            "ok": false,
            "code": code,
            "message": message,
            "request_id": request_id
        })
        .to_string(),
    )
}

fn is_authorized(req: &HttpRequest, admin_token: Option<&str>) -> bool {
    match admin_token {
        None => true,
        Some(token) => {
            let auth = req
                .headers
                .get("authorization")
                .map(String::as_str)
                .unwrap_or("");
            let expected = format!("Bearer {}", token);
            auth == expected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_decode_and_query_parse() {
        let q = "sid=S-1-5-21%2Dabc&category=auth+event&limit=10";
        let p = parse_query(q);
        assert_eq!(p.get("sid").map(String::as_str), Some("S-1-5-21-abc"));
        assert_eq!(p.get("category").map(String::as_str), Some("auth event"));
        assert_eq!(p.get("limit").map(String::as_str), Some("10"));
    }

    #[test]
    fn test_authorization_check() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("authorization".to_string(), "Bearer secret".to_string());
        let req = HttpRequest {
            method: "GET".to_string(),
            path: "/audit".to_string(),
            query: None,
            headers,
            body: vec![],
        };
        assert!(is_authorized(&req, Some("secret")));
        assert!(!is_authorized(&req, Some("wrong")));
        assert!(is_authorized(&req, None));
    }

    #[test]
    fn test_paging_parse_guard() {
        let mut p = std::collections::HashMap::new();
        p.insert("limit".to_string(), "-1".to_string());
        p.insert("offset".to_string(), "-9".to_string());
        assert_eq!(parse_limit(&p, 100, 1000), 100);
        assert_eq!(parse_offset(&p), 0);

        p.insert("limit".to_string(), "99999".to_string());
        p.insert("offset".to_string(), "55".to_string());
        assert_eq!(parse_limit(&p, 100, 1000), 1000);
        assert_eq!(parse_offset(&p), 55);
    }

    #[test]
    fn test_input_validation_rules() {
        assert!(validate_user_name("user_01").is_ok());
        assert!(validate_user_name("bad user").is_err());
        assert!(validate_scope("global").is_ok());
        assert!(validate_scope("bad/scope").is_err());
        assert!(validate_scope_id("S-1-5-21-1000").is_ok());
        assert!(validate_scope_id("bad scope id").is_err());
        assert!(validate_key_id("not-uuid").is_err());
        assert!(validate_event_code("1100").is_ok());
        assert!(validate_event_code("11AA").is_err());
    }
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for kv in query.split('&') {
        if kv.is_empty() {
            continue;
        }
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

fn opt_nonempty<'a>(
    params: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    params
        .get(key)
        .map(String::as_str)
        .and_then(|s| if s.is_empty() { None } else { Some(s) })
}

fn is_valid_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

fn validate_user_name(user: &str) -> std::result::Result<(), String> {
    if user.is_empty() || user.len() > 64 {
        return Err("user must be 1..64 chars".to_string());
    }
    if !user.chars().all(is_valid_name_char) {
        return Err("user contains invalid characters".to_string());
    }
    Ok(())
}

fn validate_scope(scope: &str) -> std::result::Result<(), String> {
    if scope.is_empty() || scope.len() > 32 {
        return Err("scope must be 1..32 chars".to_string());
    }
    if !scope.chars().all(is_valid_name_char) {
        return Err("scope contains invalid characters".to_string());
    }
    Ok(())
}

fn validate_scope_id(scope_id: &str) -> std::result::Result<(), String> {
    if scope_id.is_empty() || scope_id.len() > 128 {
        return Err("scope_id must be 1..128 chars".to_string());
    }
    if !scope_id
        .chars()
        .all(|c| is_valid_name_char(c) || c == ':' || c == '/')
    {
        return Err("scope_id contains invalid characters".to_string());
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> std::result::Result<(), String> {
    if uuid::Uuid::parse_str(key_id).is_err() {
        return Err("key_id must be UUID".to_string());
    }
    Ok(())
}

fn validate_sid(sid: &str) -> std::result::Result<(), String> {
    if sid.is_empty() || sid.len() > 128 {
        return Err("sid must be 1..128 chars".to_string());
    }
    if !sid
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err("sid contains invalid characters".to_string());
    }
    Ok(())
}

fn validate_simple_token(
    name: &str,
    value: &str,
    max_len: usize,
) -> std::result::Result<(), String> {
    if value.is_empty() || value.len() > max_len {
        return Err(format!("{} must be 1..{} chars", name, max_len));
    }
    if !value.chars().all(is_valid_name_char) {
        return Err(format!("{} contains invalid characters", name));
    }
    Ok(())
}

fn validate_event_code(code: &str) -> std::result::Result<(), String> {
    if code.len() != 4 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err("code must be 4 digits".to_string());
    }
    Ok(())
}

fn parse_limit(params: &std::collections::HashMap<String, String>, default: i64, max: i64) -> i64 {
    let parsed = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default);
    parsed.min(max)
}

fn parse_offset(params: &std::collections::HashMap<String, String>) -> i64 {
    params
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(0)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h1 = bytes[i + 1];
                let h2 = bytes[i + 2];
                let n1 = hex_val(h1);
                let n2 = hex_val(h2);
                if let (Some(a), Some(b)) = (n1, n2) {
                    out.push((a << 4) | b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn validate_pubkey(pubkey: &str) -> Result<()> {
    let parts: Vec<&str> = pubkey.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow!("missing key body"));
    }
    parse_public_key_base64(parts[1]).map_err(|e| anyhow!("{}", e))?;
    Ok(())
}

fn validate_acl_path(path: &str) -> std::result::Result<(), String> {
    if path.is_empty() || path.len() > 512 {
        return Err("path must be 1..512 chars".to_string());
    }
    if path.contains('\0') || path.contains("..") {
        return Err("path contains invalid sequence".to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn query_acl(path: &str, mode: &str) -> Result<serde_json::Value> {
    if mode == "simple" {
        let md = std::fs::metadata(path)?;
        let perms = if md.permissions().readonly() {
            if md.is_dir() {
                "r-xr-xr-x"
            } else {
                "r--r--r--"
            }
        } else if md.is_dir() {
            "rwxr-xr-x"
        } else {
            "rw-r--r--"
        };
        return Ok(json!({
            "mode": "simple",
            "is_dir": md.is_dir(),
            "readonly": md.permissions().readonly(),
            "posix_like": perms
        }));
    }
    let command = format!(
        "$p='{}'; $acl=Get-Acl -Path $p; $rules=$acl.Access | Select-Object IdentityReference,FileSystemRights,AccessControlType,IsInherited; $obj=[PSCustomObject]@{{ owner=$acl.Owner; rules=$rules }}; $obj | ConvertTo-Json -Depth 4",
        path.replace('\'', "''")
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "powershell exit={}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(value)
}

#[cfg(windows)]
fn check_user_acls_api(user: &str) -> Result<serde_json::Value> {
    use std::path::Path;
    use vlt_sshd::acl_diagnose;

    let info = get_user_info_internal(user)?;
    let ssh_dir = Path::new(&info.profile_path).join(".ssh");
    let authorized_keys = ssh_dir.join("authorized_keys");
    let admin_keys = Path::new("C:\\ProgramData\\ssh\\administrators_authorized_keys");

    let mut results = Vec::new();
    if ssh_dir.exists() {
        results.push(acl_diagnose::diagnose_path(&ssh_dir, Some(&info.sid))?);
    }
    if authorized_keys.exists() {
        results.push(acl_diagnose::diagnose_path(
            &authorized_keys,
            Some(&info.sid),
        )?);
    }
    if info.is_admin && admin_keys.exists() {
        results.push(acl_diagnose::diagnose_path(&admin_keys, None)?);
    }

    Ok(serde_json::to_value(results)?)
}

#[cfg(windows)]
struct InternalUserInfo {
    sid: String,
    profile_path: String,
    is_admin: bool,
}

#[cfg(windows)]
fn get_user_info_internal(user: &str) -> Result<InternalUserInfo> {
    use std::process::Command;
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $u = New-Object System.Security.Principal.NTAccount({}); \
         $sid = $u.Translate([System.Security.Principal.SecurityIdentifier]).Value; \
         $p = (Get-CimInstance Win32_UserProfile -Filter \"SID = '$sid'\").LocalPath; \
         $isAdmin = (New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator); \
         @{{sid=$sid; profile_path=$p; is_admin=$isAdmin}} | ConvertTo-Json -Compress",
        serde_json::to_string(user).unwrap()
    );

    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()?;

    if !out.status.success() {
        return Err(anyhow!(
            "Failed to get user info: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(InternalUserInfo {
        sid: v["sid"]
            .as_str()
            .ok_or_else(|| anyhow!("missing sid"))?
            .to_string(),
        profile_path: v["profile_path"]
            .as_str()
            .ok_or_else(|| anyhow!("missing path"))?
            .to_string(),
        is_admin: v["is_admin"].as_bool().unwrap_or(false),
    })
}

#[cfg(not(windows))]
fn check_user_acls_api(_user: &str) -> Result<serde_json::Value> {
    Err(anyhow!("acl check is supported only on windows"))
}

#[cfg(not(windows))]
fn query_acl(_path: &str, _mode: &str) -> Result<serde_json::Value> {
    Err(anyhow!("acl endpoint is supported only on windows"))
}

fn normalize_constraints_json(raw: &str) -> std::result::Result<String, String> {
    let parsed = serde_json::from_str::<KeyConstraints>(raw)
        .map_err(|e| format!("constraints must be JSON object: {}", e))?;
    if let Some(c) = parsed.comment.as_deref() {
        if c.len() > 128 {
            return Err("comment must be <= 128 chars".to_string());
        }
    }
    if let Some(u) = parsed.use_case.as_deref() {
        if u.len() > 64 {
            return Err("use_case must be <= 64 chars".to_string());
        }
    }
    if let Some(tags) = parsed.tags.as_ref() {
        if tags.len() > 16 {
            return Err("tags must be <= 16 entries".to_string());
        }
        if tags.iter().any(|t| t.is_empty() || t.len() > 32) {
            return Err("each tag must be 1..32 chars".to_string());
        }
    }
    serde_json::to_string(&parsed).map_err(|e| format!("constraints serialize error: {}", e))
}

const ADMIN_UI_HTML: &str = r#"<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>WinNative-SSH Admin UI</title>
  <style>
    body { font-family: "Segoe UI", "Yu Gothic UI", sans-serif; margin: 16px; background:#f5f7fb; color:#1f2937; }
    .card { background:#fff; border:1px solid #dbe1ea; border-radius:8px; padding:12px; margin-bottom:12px; }
    h1 { margin:0 0 10px 0; font-size:20px; }
    h2 { margin:0 0 8px 0; font-size:16px; }
    input, button, select { padding:6px 8px; margin-right:6px; }
    table { width:100%; border-collapse: collapse; font-size:12px; }
    th, td { border:1px solid #dbe1ea; padding:6px; text-align:left; }
    .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:8px; }
    .muted { color:#6b7280; font-size:12px; }
  </style>
</head>
<body>
  <h1>WinNative-SSH Admin UI</h1>
  <div class="card">
    <div class="row">
      <label>Token</label><input id="token" type="password" size="48" />
      <button onclick="refreshAll()">Refresh All</button>
    </div>
    <div class="muted">Token は WNSSH_ADMIN_TOKEN を入力</div>
  </div>

  <div class="card">
    <h2>Users</h2>
    <div class="row">
      <label>Offset</label><input id="usersOffset" value="0" size="6" />
      <button onclick="loadUsers()">Load Users</button>
    </div>
    <table id="users"></table>
  </div>

  <div class="card">
    <h2>User Control</h2>
    <div class="row">
      <label>User</label><input id="ctlUser" value="" />
      <button onclick="disableUser()">Disable</button>
      <button onclick="enableUser()">Enable</button>
    </div>
  </div>

  <div class="card">
    <h2>Keys</h2>
    <div class="row">
      <label>User</label><input id="keyUser" value="" />
      <label>Offset</label><input id="keysOffset" value="0" size="6" />
      <button onclick="loadKeys()">Load Keys</button>
    </div>
    <div class="row">
      <label>New PubKey</label><input id="newPubKey" size="96" />
      <button onclick="addKey()">Add Key</button>
    </div>
    <table id="keys"></table>
  </div>

  <div class="card">
    <h2>Sessions</h2>
    <div class="row">
      <label>SID Filter</label><input id="sidFilter" size="28" />
      <label>Offset</label><input id="sessionsOffset" value="0" size="6" />
      <button onclick="loadSessions()">Load Sessions</button>
    </div>
    <table id="sessions"></table>
  </div>

  <div class="card">
    <h2>Audit</h2>
    <div class="row">
      <label>Category</label><input id="auditCategory" size="12" />
      <label>Code</label><input id="auditCode" size="8" />
      <label>Offset</label><input id="auditOffset" value="0" size="6" />
      <button onclick="loadAudit()">Load Audit</button>
    </div>
    <table id="audit"></table>
  </div>

  <div class="card">
    <h2>Policies</h2>
    <div class="row">
      <label>Scope</label><input id="policyScope" size="12" />
      <label>ScopeId</label><input id="policyScopeId" size="24" />
      <label>Offset</label><input id="policyOffset" value="0" size="6" />
      <button onclick="loadPolicies()">Load Policies</button>
    </div>
    <table id="policies"></table>
  </div>

  <script>
    function tokenHeader() { return { "Authorization": "Bearer " + (document.getElementById("token").value || "") }; }
    async function api(path) {
      const res = await fetch(path, { headers: tokenHeader() });
      return await res.json();
    }
    async function post(path, body) {
      const res = await fetch(path, {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, tokenHeader()),
        body: JSON.stringify(body)
      });
      return await res.json();
    }
    function q(id) { return encodeURIComponent(document.getElementById(id).value || ""); }
    function renderTable(id, rows) {
      const table = document.getElementById(id);
      if (!rows || rows.length === 0) { table.innerHTML = "<tr><td>(empty)</td></tr>"; return; }
      const cols = Object.keys(rows[0]);
      let html = "<tr>" + cols.map(c => "<th>"+c+"</th>").join("") + "</tr>";
      for (const r of rows) {
        html += "<tr>" + cols.map(c => "<td>"+String(r[c] ?? "")+"</td>").join("") + "</tr>";
      }
      table.innerHTML = html;
    }
    async function loadUsers() { const d = await api("/users?limit=50&offset="+q("usersOffset")); renderTable("users", d.users || []); }
    async function loadKeys() { const d = await api("/keys?user="+q("keyUser")+"&limit=50&offset="+q("keysOffset")); renderTable("keys", d.keys || []); }
    async function loadSessions() {
      const sid = document.getElementById("sidFilter").value || "";
      const d = await api("/sessions?sid="+encodeURIComponent(sid)+"&limit=50&offset="+q("sessionsOffset"));
      renderTable("sessions", d.sessions || []);
    }
    async function loadAudit() {
      const c = document.getElementById("auditCategory").value || "";
      const code = document.getElementById("auditCode").value || "";
      const d = await api("/audit?category="+encodeURIComponent(c)+"&code="+encodeURIComponent(code)+"&limit=50&offset="+q("auditOffset"));
      renderTable("audit", d.events || []);
    }
    async function loadPolicies() {
      const s = document.getElementById("policyScope").value || "";
      const sid = document.getElementById("policyScopeId").value || "";
      const d = await api("/policies?scope="+encodeURIComponent(s)+"&scope_id="+encodeURIComponent(sid)+"&limit=50&offset="+q("policyOffset"));
      renderTable("policies", d.policies || []);
    }
    async function disableUser() { await post("/disable-user", { user: document.getElementById("ctlUser").value }); await loadUsers(); }
    async function enableUser() { await post("/enable-user", { user: document.getElementById("ctlUser").value }); await loadUsers(); }
    async function addKey() {
      await post("/add-key", { user: document.getElementById("keyUser").value, pubkey: document.getElementById("newPubKey").value });
      await loadKeys();
    }
    async function refreshAll() { await loadUsers(); await loadKeys(); await loadSessions(); await loadAudit(); await loadPolicies(); }
  </script>
</body>
</html>
"#;
