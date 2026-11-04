//! Instance settings (branding, registration, features, verified domains) and the
//! admin API. Admins manage the instance and accounts; they can never read vaults,
//! which stay end-to-end encrypted with each user's own key.

use crate::api::{authenticate_req, ApiError, Shared, Signups};
use crate::db::{self, now_ms};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;

type ApiResult = Result<Json<Value>, ApiError>;

const META_KEY: &str = "instance";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InstanceSettings {
    /// Display name shown in clients ("Keyhaven" by default).
    pub name: String,
    pub tagline: String,
    /// "" (neutral) or "#rrggbb".
    pub accent: String,
    /// PNG data URL, or "".
    pub logo: String,
    /// Banner shown to every signed-in user ("" = none).
    pub notice: String,
    /// None = use KEYHAVEN_SIGNUPS from the environment.
    pub signups: Option<String>,
    pub icons_enabled: bool,
    /// None = clients use their built-in list.
    pub verified_domains: Option<Vec<String>>,
}

impl Default for InstanceSettings {
    fn default() -> Self {
        Self {
            name: "Keyhaven".into(),
            tagline: String::new(),
            accent: String::new(),
            logo: String::new(),
            notice: String::new(),
            signups: None,
            icons_enabled: true,
            verified_domains: None,
        }
    }
}

pub fn load(c: &Connection) -> InstanceSettings {
    db::get_meta(c, META_KEY)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default()
}

fn save(c: &Connection, s: &InstanceSettings) -> Result<(), ApiError> {
    db::set_meta(c, META_KEY, &serde_json::to_string(s)?)?;
    Ok(())
}

/// Effective registration mode: admin setting, else the environment default.
pub fn signups(c: &Connection, env_default: Signups) -> Signups {
    match load(c).signups.as_deref() {
        Some("open") => Signups::Open,
        Some("closed") => Signups::Closed,
        Some("invite") => Signups::Invite,
        _ => env_default,
    }
}

pub fn signups_str(s: Signups) -> &'static str {
    match s {
        Signups::Open => "open",
        Signups::Invite => "invite",
        Signups::Closed => "closed",
    }
}

/// Public branding (also served unauthenticated so sign-in screens can show it).
pub fn branding(s: &InstanceSettings) -> Value {
    json!({ "name": s.name, "tagline": s.tagline, "accent": s.accent, "logo": s.logo })
}

fn clean_text(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control() || *c == '\n').take(max).collect::<String>().trim().to_string()
}

fn valid_domain(d: &str) -> bool {
    crate::icons::host_ok(d) && d.len() <= 253
}

// ---------- auth helpers ----------

struct Admin {
    user_id: String,
}

fn require_admin(st: &Shared, headers: &HeaderMap, addr: &SocketAddr) -> Result<Admin, ApiError> {
    let a = authenticate_req(st, headers, addr)?;
    let user = db::user_by_id(&st.db.lock().unwrap(), &a.user_id)?.ok_or_else(ApiError::unauthorized)?;
    if user.role != "admin" {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Admins only"));
    }
    Ok(Admin { user_id: a.user_id })
}

// ---------- signed-in users ----------

/// GET /api/instance — branding, notice, features and verified domains for any signed-in user.
pub async fn instance(State(st): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    let a = authenticate_req(&st, &headers, &addr)?;
    let db = st.db.lock().unwrap();
    let role = db::user_by_id(&db, &a.user_id)?.map(|u| u.role).unwrap_or_default();
    let s = load(&db);
    Ok(Json(json!({
        "branding": branding(&s),
        "notice": s.notice,
        "iconsEnabled": s.icons_enabled,
        "verifiedDomains": s.verified_domains,
        "role": role,
    })))
}

// ---------- admin ----------

pub async fn overview(State(st): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    let db = st.db.lock().unwrap();
    let s = load(&db);
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "users": db::user_count(&db)?,
        "admins": db::admin_count(&db)?,
        "items": db::total_items(&db)?,
        "dbBytes": db::db_bytes(&db)?,
        "signups": signups_str(signups(&db, st.signups)),
        "signupsFromEnv": s.signups.is_none(),
        "envSignups": signups_str(st.signups),
    })))
}

pub async fn get_settings(State(st): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    let s = load(&st.db.lock().unwrap());
    Ok(Json(serde_json::to_value(s)?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPatch {
    name: Option<String>,
    tagline: Option<String>,
    accent: Option<String>,
    notice: Option<String>,
    /// "open" | "invite" | "closed" | "env"
    signups: Option<String>,
    icons_enabled: Option<bool>,
}

pub async fn put_settings(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(p): Json<SettingsPatch>,
) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    let db = st.db.lock().unwrap();
    let mut s = load(&db);
    if let Some(n) = p.name {
        let n = clean_text(&n, 40);
        s.name = if n.is_empty() { "Keyhaven".into() } else { n };
    }
    if let Some(t) = p.tagline {
        s.tagline = clean_text(&t, 120);
    }
    if let Some(a) = p.accent {
        let a = a.trim().to_ascii_lowercase();
        if !a.is_empty() && !(a.len() == 7 && a.starts_with('#') && a[1..].chars().all(|c| c.is_ascii_hexdigit())) {
            return Err(ApiError::bad("Accent colour must look like #3b82f6"));
        }
        s.accent = a;
    }
    if let Some(n) = p.notice {
        s.notice = clean_text(&n, 500);
    }
    if let Some(m) = p.signups {
        s.signups = match m.as_str() {
            "open" | "invite" | "closed" => Some(m),
            "env" => None,
            _ => return Err(ApiError::bad("Unknown registration mode")),
        };
    }
    if let Some(i) = p.icons_enabled {
        s.icons_enabled = i;
    }
    save(&db, &s)?;
    Ok(Json(serde_json::to_value(s)?))
}

#[derive(Deserialize)]
pub struct LogoReq {
    image: String,
}

pub async fn put_logo(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(r): Json<LogoReq>,
) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    let raw = r.image.split_once("base64,").map(|x| x.1).unwrap_or(&r.image);
    let bytes = B64.decode(raw.trim()).map_err(|_| ApiError::bad("Logo must be base64 image data"))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(ApiError::bad("Logo must be under 2 MB"));
    }
    let (png, mime) = crate::icons::normalize_to(bytes, 128).ok_or_else(|| ApiError::bad("Unsupported image (use PNG, JPEG, WebP, GIF or ICO)"))?;
    if mime != "image/png" {
        return Err(ApiError::bad("SVG logos aren't supported; upload a PNG"));
    }
    let db = st.db.lock().unwrap();
    let mut s = load(&db);
    s.logo = format!("data:image/png;base64,{}", B64.encode(png));
    save(&db, &s)?;
    Ok(Json(json!({ "logo": s.logo })))
}

pub async fn delete_logo(State(st): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    let db = st.db.lock().unwrap();
    let mut s = load(&db);
    s.logo.clear();
    save(&db, &s)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct VerifiedReq {
    /// null resets to the built-in list.
    domains: Option<Vec<String>>,
}

pub async fn put_verified(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(r): Json<VerifiedReq>,
) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    let domains = match r.domains {
        None => None,
        Some(list) => {
            if list.len() > 5000 {
                return Err(ApiError::bad("At most 5000 domains"));
            }
            let mut out: Vec<String> = Vec::new();
            for d in list {
                let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
                let d = d.strip_prefix("www.").unwrap_or(&d).to_string();
                if d.is_empty() {
                    continue;
                }
                if !valid_domain(&d) {
                    return Err(ApiError::bad(format!("“{d}” is not a valid domain")));
                }
                if !out.contains(&d) {
                    out.push(d);
                }
            }
            out.sort();
            Some(out)
        }
    };
    let db = st.db.lock().unwrap();
    let mut s = load(&db);
    s.verified_domains = domains;
    save(&db, &s)?;
    Ok(Json(json!({ "verifiedDomains": s.verified_domains })))
}

pub async fn users(State(st): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    let me = require_admin(&st, &headers, &addr)?;
    let list = db::admin_users(&st.db.lock().unwrap())?;
    Ok(Json(json!({ "users": list, "me": me.user_id })))
}

#[derive(Deserialize)]
pub struct RoleReq {
    role: String,
}

pub async fn set_role(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(r): Json<RoleReq>,
) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    if r.role != "admin" && r.role != "user" {
        return Err(ApiError::bad("Role must be admin or user"));
    }
    let db = st.db.lock().unwrap();
    let target = db::user_by_id(&db, &id)?.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "User not found"))?;
    if target.role == "admin" && r.role == "user" && db::admin_count(&db)? <= 1 {
        return Err(ApiError::bad("You can't remove the last admin"));
    }
    db::set_role(&db, &id, &r.role)?;
    eprintln!("admin: {} is now {}", target.email, r.role);
    Ok(Json(json!({ "ok": true })))
}

pub async fn sign_out_user(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let me = require_admin(&st, &headers, &addr)?;
    if me.user_id == id {
        return Err(ApiError::bad("Use Settings → Devices to sign out your own sessions"));
    }
    let n = db::delete_user_sessions(&st.db.lock().unwrap(), &id)?;
    Ok(Json(json!({ "revoked": n })))
}

pub async fn delete_user(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let me = require_admin(&st, &headers, &addr)?;
    if me.user_id == id {
        return Err(ApiError::bad("Delete your own account from Settings → Account"));
    }
    let db = st.db.lock().unwrap();
    let target = db::user_by_id(&db, &id)?.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "User not found"))?;
    if target.role == "admin" && db::admin_count(&db)? <= 1 {
        return Err(ApiError::bad("You can't delete the last admin"));
    }
    db::delete_user(&db, &id)?;
    eprintln!("admin: deleted account {}", target.email);
    Ok(Json(json!({ "ok": true })))
}

pub async fn invites(State(st): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    Ok(Json(json!({ "invites": db::list_invites(&st.db.lock().unwrap())?, "now": now_ms() })))
}

#[derive(Deserialize)]
pub struct InviteReq {
    days: Option<i64>,
}

pub async fn create_invite(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(r): Json<InviteReq>,
) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    let days = r.days.unwrap_or(7).clamp(1, 365);
    let code = crate::api::create_invite(&st.db.lock().unwrap(), days)?;
    Ok(Json(json!({ "code": code, "days": days })))
}

pub async fn delete_invite(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    require_admin(&st, &headers, &addr)?;
    if !db::delete_invite(&st.db.lock().unwrap(), &id)? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Invite not found"));
    }
    Ok(Json(json!({ "ok": true })))
}
