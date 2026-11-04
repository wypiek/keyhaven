//! HTTP API. All vault content arrives already encrypted by the client; the server
//! authenticates users with a key *derived* from the master password (never the password
//! itself) and stores only ciphertext.

use crate::db::{self, now_ms};
use crate::ratelimit::Limiter;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Signups {
    Open,
    Invite,
    Closed,
}

pub struct AppState {
    pub db: Mutex<Connection>,
    pub secret: [u8; 32],
    pub signups: Signups,
    pub trust_proxy: bool,
    pub limiter: Limiter,
    pub icon_slots: tokio::sync::Semaphore,
}

pub type Shared = Arc<AppState>;

// ---------- errors ----------

pub struct ApiError(StatusCode, String);

impl ApiError {
    pub(crate) fn new(code: StatusCode, msg: impl Into<String>) -> Self {
        Self(code, msg.into())
    }
    pub(crate) fn bad(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    pub(crate) fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Not signed in or session expired")
    }
}

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(e: E) -> Self {
        eprintln!("internal error: {e}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

// ---------- helpers ----------

fn client_ip(st: &AppState, headers: &HeaderMap, addr: &SocketAddr) -> String {
    if st.trust_proxy {
        if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            return v.trim().to_string();
        }
        if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(last) = v.split(',').map(str::trim).filter(|s| !s.is_empty()).next_back() {
                return last.to_string();
            }
        }
    }
    addr.ip().to_string()
}

fn normalize_email(e: &str) -> Result<String, ApiError> {
    let e = e.trim().to_lowercase();
    let valid = e.len() <= 254
        && e.split_once('@')
            .map(|(l, d)| !l.is_empty() && d.contains('.') && !d.starts_with('.') && !d.ends_with('.'))
            .unwrap_or(false)
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    if !valid {
        return Err(ApiError::bad("Enter a valid email address"));
    }
    Ok(e)
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn server_argon() -> Argon2<'static> {
    // The client already ran a memory-hard KDF; this is defence in depth for a DB leak.
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19 * 1024, 2, 1, None).unwrap())
}

fn decode_auth_key(b64: &str) -> Result<Vec<u8>, ApiError> {
    match B64.decode(b64.trim()) {
        Ok(v) if v.len() == 32 => Ok(v),
        _ => Err(ApiError::bad("Malformed authentication key")),
    }
}

async fn hash_auth_key(key: Vec<u8>) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        server_argon().hash_password(&key, &salt).map(|h| h.to_string())
    })
    .await?
    .map_err(|e| ApiError::from(e.to_string()))
}

async fn verify_auth_key(key: Vec<u8>, stored: String) -> Result<bool, ApiError> {
    Ok(tokio::task::spawn_blocking(move || {
        PasswordHash::new(&stored)
            .map(|h| server_argon().verify_password(&key, &h).is_ok())
            .unwrap_or(false)
    })
    .await?)
}

/// Validate client-supplied KDF parameters so a malicious client can't weaken its own
/// account below sane minimums or make other clients hang.
fn validate_kdf(v: &Value) -> Result<String, ApiError> {
    let alg = v.get("algorithm").and_then(Value::as_str).unwrap_or("");
    let mem = v.get("memory").and_then(Value::as_u64).unwrap_or(0);
    let it = v.get("iterations").and_then(Value::as_u64).unwrap_or(0);
    let par = v.get("parallelism").and_then(Value::as_u64).unwrap_or(0);
    let salt = v.get("salt").and_then(Value::as_str).and_then(|s| B64.decode(s).ok());
    if alg != "argon2id"
        || !(16 * 1024..=1024 * 1024).contains(&mem)
        || !(2..=20).contains(&it)
        || !(1..=8).contains(&par)
        || !salt.map(|s| (16..=64).contains(&s.len())).unwrap_or(false)
    {
        return Err(ApiError::bad("Invalid key-derivation parameters"));
    }
    Ok(json!({ "algorithm": "argon2id", "memory": mem, "iterations": it, "parallelism": par,
               "salt": v["salt"] })
    .to_string())
}

fn validate_wrapped(s: &str) -> Result<(), ApiError> {
    if s.starts_with("v1.") && s.len() < 512 && s.split('.').count() == 3 {
        Ok(())
    } else {
        Err(ApiError::bad("Malformed wrapped key"))
    }
}

fn validate_item_id(id: &str) -> Result<(), ApiError> {
    if !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        Ok(())
    } else {
        Err(ApiError::bad("Invalid item id"))
    }
}

const MAX_ITEM_BYTES: usize = 1024 * 1024;
const MAX_ITEMS: i64 = 20_000;

fn validate_item_data(d: &str) -> Result<(), ApiError> {
    if d.starts_with("v1.") && d.len() <= MAX_ITEM_BYTES {
        Ok(())
    } else {
        Err(ApiError::bad("Item data must be client-encrypted and under 1 MiB"))
    }
}

fn new_token() -> (String, String) {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = B64URL.encode(raw);
    let hash = sha256_hex(token.as_bytes());
    (token, hash)
}

pub struct Authed {
    pub user_id: String,
    pub session_id: String,
}

fn authenticate(st: &AppState, headers: &HeaderMap, ip: &str) -> Result<Authed, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)?;
    let hash = sha256_hex(token.trim().as_bytes());
    let db = st.db.lock().unwrap();
    match db::touch_session(&db, &hash, ip)? {
        Some((session_id, user_id)) => Ok(Authed { user_id, session_id }),
        None => Err(ApiError::unauthorized()),
    }
}

fn device_name(s: Option<&str>) -> String {
    let d: String = s.unwrap_or("Unknown device").chars().filter(|c| !c.is_control()).take(80).collect();
    if d.trim().is_empty() {
        "Unknown device".into()
    } else {
        d
    }
}

fn create_session(st: &AppState, user_id: &str, device: &str, ip: &str) -> Result<String, ApiError> {
    let (token, hash) = new_token();
    let db = st.db.lock().unwrap();
    db::insert_session(&db, &uuid::Uuid::new_v4().to_string(), user_id, &hash, device, ip)?;
    Ok(token)
}

// ---------- public endpoints ----------

/// Authenticate a request (shared with the admin module).
pub(crate) fn authenticate_req(st: &AppState, headers: &HeaderMap, addr: &SocketAddr) -> Result<Authed, ApiError> {
    let ip = client_ip(st, headers, addr);
    authenticate(st, headers, &ip)
}

pub async fn config(State(st): State<Shared>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let first = db::user_count(&db)? == 0;
    let settings = crate::admin::load(&db);
    let signups = match (first, crate::admin::signups(&db, st.signups)) {
        (true, _) | (_, Signups::Open) => "open",
        (_, Signups::Invite) => "invite",
        (_, Signups::Closed) => "closed",
    };
    // "name" stays "Keyhaven": clients use it to recognise the server. Display name is in branding.
    Ok(Json(json!({ "name": "Keyhaven", "version": env!("CARGO_PKG_VERSION"), "signups": signups,
                    "branding": crate::admin::branding(&settings) })))
}

#[derive(Deserialize)]
pub struct PreloginReq {
    email: String,
}

/// Returns the KDF parameters for an account. Unknown emails get deterministic fake
/// parameters so the endpoint cannot be used to discover which emails have accounts.
pub async fn prelogin(State(st): State<Shared>, Json(r): Json<PreloginReq>) -> ApiResult {
    let email = normalize_email(&r.email)?;
    let user = db::user_by_email(&st.db.lock().unwrap(), &email)?;
    if let Some(u) = user {
        let kdf: Value = serde_json::from_str(&u.kdf)?;
        return Ok(Json(json!({ "kdf": kdf })));
    }
    let mut mac = <Hmac<Sha256>>::new_from_slice(&st.secret).unwrap();
    mac.update(b"fake-salt:");
    mac.update(email.as_bytes());
    let salt = B64.encode(&mac.finalize().into_bytes()[..16]);
    Ok(Json(json!({ "kdf": { "algorithm": "argon2id", "memory": 65536, "iterations": 3,
                             "parallelism": 4, "salt": salt } })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterReq {
    email: String,
    auth_key: String,
    kdf: Value,
    wrapped_key: String,
    invite_code: Option<String>,
    device: Option<String>,
}

pub async fn register(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(r): Json<RegisterReq>,
) -> ApiResult {
    let ip = client_ip(&st, &headers, &addr);
    st.limiter.check(&format!("register:{ip}"), 10, Duration::from_secs(3600))?;
    st.limiter.fail(&format!("register:{ip}"));
    let email = normalize_email(&r.email)?;
    let kdf = validate_kdf(&r.kdf)?;
    validate_wrapped(&r.wrapped_key)?;
    let key = decode_auth_key(&r.auth_key)?;
    let auth_hash = hash_auth_key(key).await?;

    let user_id = uuid::Uuid::new_v4().to_string();
    {
        let db = st.db.lock().unwrap();
        if db::user_by_email(&db, &email)?.is_some() {
            return Err(ApiError::new(StatusCode::CONFLICT, "An account with this email already exists"));
        }
        let first = db::user_count(&db)? == 0;
        if !first {
            match crate::admin::signups(&db, st.signups) {
                Signups::Open => {}
                Signups::Closed => {
                    return Err(ApiError::new(StatusCode::FORBIDDEN, "Registration is disabled on this server"))
                }
                Signups::Invite => {
                    let code = r.invite_code.as_deref().unwrap_or("").trim().to_uppercase();
                    if code.is_empty() || !db::consume_invite(&db, &sha256_hex(code.as_bytes()), &email)? {
                        return Err(ApiError::new(
                            StatusCode::FORBIDDEN,
                            "A valid invite code is required. Ask the server admin to run `keyhaven-server invite`.",
                        ));
                    }
                }
            }
        }
        db::insert_user(
            &db,
            &db::User {
                id: user_id.clone(),
                email: email.clone(),
                kdf,
                auth_hash,
                wrapped_key: r.wrapped_key.clone(),
                revision: 0,
                created_at: now_ms(),
                role: if first { "admin" } else { "user" }.into(),
            },
        )?;
    }
    let token = create_session(&st, &user_id, &device_name(r.device.as_deref()), &ip)?;
    eprintln!("new account registered from {ip}");
    Ok(Json(json!({ "token": token, "userId": user_id, "email": email })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginReq {
    email: String,
    auth_key: String,
    device: Option<String>,
}

pub async fn login(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(r): Json<LoginReq>,
) -> ApiResult {
    let ip = client_ip(&st, &headers, &addr);
    let email = normalize_email(&r.email)?;
    let (k_ip, k_email) = (format!("login-ip:{ip}"), format!("login-email:{email}"));
    st.limiter.check(&k_ip, 20, Duration::from_secs(900))?;
    st.limiter.check(&k_email, 10, Duration::from_secs(900))?;
    let key = decode_auth_key(&r.auth_key)?;
    let user = db::user_by_email(&st.db.lock().unwrap(), &email)?;
    let ok = match &user {
        Some(u) => verify_auth_key(key, u.auth_hash.clone()).await?,
        None => {
            // Spend comparable time so response timing doesn't reveal unknown accounts.
            let _ = hash_auth_key(key).await;
            false
        }
    };
    let Some(user) = user.filter(|_| ok) else {
        st.limiter.fail(&k_ip);
        st.limiter.fail(&k_email);
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Incorrect email or master password"));
    };
    st.limiter.reset(&k_email);
    let token = create_session(&st, &user.id, &device_name(r.device.as_deref()), &ip)?;
    Ok(Json(json!({
        "token": token,
        "userId": user.id,
        "email": user.email,
        "kdf": serde_json::from_str::<Value>(&user.kdf)?,
        "wrappedKey": user.wrapped_key,
    })))
}

// ---------- authenticated endpoints ----------

macro_rules! authed {
    ($st:expr, $headers:expr, $addr:expr) => {{
        let ip = client_ip(&$st, &$headers, &$addr);
        authenticate(&$st, &$headers, &ip)?
    }};
}

pub async fn logout(State(st): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    let a = authed!(st, headers, addr);
    db::delete_session(&st.db.lock().unwrap(), &a.user_id, &a.session_id)?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn account(State(st): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    let a = authed!(st, headers, addr);
    let db = st.db.lock().unwrap();
    let u = db::user_by_id(&db, &a.user_id)?.ok_or_else(ApiError::unauthorized)?;
    Ok(Json(json!({
        "userId": u.id, "email": u.email, "kdf": serde_json::from_str::<Value>(&u.kdf)?,
        "wrappedKey": u.wrapped_key, "revision": u.revision, "createdAt": u.created_at, "role": u.role,
        "itemCount": db::item_count(&db, &u.id)?,
    })))
}

async fn reverify(st: &AppState, user_id: &str, auth_key: &str) -> Result<db::User, ApiError> {
    let key = format!("reverify:{user_id}");
    st.limiter.check(&key, 10, Duration::from_secs(900))?;
    let u = db::user_by_id(&st.db.lock().unwrap(), user_id)?.ok_or_else(ApiError::unauthorized)?;
    if !verify_auth_key(decode_auth_key(auth_key)?, u.auth_hash.clone()).await? {
        st.limiter.fail(&key);
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Current master password is incorrect"));
    }
    st.limiter.reset(&key);
    Ok(u)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordReq {
    auth_key: String,
    new_auth_key: String,
    new_kdf: Value,
    new_wrapped_key: String,
}

pub async fn change_password(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(r): Json<ChangePasswordReq>,
) -> ApiResult {
    let a = authed!(st, headers, addr);
    reverify(&st, &a.user_id, &r.auth_key).await?;
    let kdf = validate_kdf(&r.new_kdf)?;
    validate_wrapped(&r.new_wrapped_key)?;
    let hash = hash_auth_key(decode_auth_key(&r.new_auth_key)?).await?;
    let db = st.db.lock().unwrap();
    db::update_credentials(&db, &a.user_id, &kdf, &hash, &r.new_wrapped_key)?;
    db::delete_other_sessions(&db, &a.user_id, &a.session_id)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountReq {
    auth_key: String,
}

pub async fn delete_account(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(r): Json<DeleteAccountReq>,
) -> ApiResult {
    let a = authed!(st, headers, addr);
    reverify(&st, &a.user_id, &r.auth_key).await?;
    db::delete_user(&st.db.lock().unwrap(), &a.user_id)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct SyncQuery {
    since: Option<i64>,
}

pub async fn sync(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<SyncQuery>,
) -> ApiResult {
    let a = authed!(st, headers, addr);
    let db = st.db.lock().unwrap();
    let revision = db::current_revision(&db, &a.user_id)?;
    let since = q.since.unwrap_or(0).max(0);
    // A client claiming to be ahead of the server (e.g. server restored from backup) does a full resync.
    let (since, full) = if since > revision { (0, true) } else { (since, since == 0) };
    let items = db::items_since(&db, &a.user_id, since)?;
    Ok(Json(json!({ "revision": revision, "full": full, "items": items })))
}

#[derive(Deserialize)]
pub struct PutItemReq {
    data: String,
}

pub async fn put_item(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(r): Json<PutItemReq>,
) -> ApiResult {
    let a = authed!(st, headers, addr);
    validate_item_id(&id)?;
    validate_item_data(&r.data)?;
    let mut db = st.db.lock().unwrap();
    if db::item_count(&db, &a.user_id)? >= MAX_ITEMS {
        return Err(ApiError::bad("Item limit reached"));
    }
    let (revision, updated_at) = db::upsert_items(&mut db, &a.user_id, &[(id, r.data)])?;
    Ok(Json(json!({ "revision": revision, "updatedAt": updated_at })))
}

#[derive(Deserialize)]
pub struct BatchItem {
    id: String,
    data: String,
}

#[derive(Deserialize)]
pub struct BatchReq {
    items: Vec<BatchItem>,
}

pub async fn put_items_batch(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(r): Json<BatchReq>,
) -> ApiResult {
    let a = authed!(st, headers, addr);
    if r.items.len() > 5000 {
        return Err(ApiError::bad("At most 5000 items per batch"));
    }
    for it in &r.items {
        validate_item_id(&it.id)?;
        validate_item_data(&it.data)?;
    }
    let mut db = st.db.lock().unwrap();
    if db::item_count(&db, &a.user_id)? + r.items.len() as i64 > MAX_ITEMS {
        return Err(ApiError::bad("Item limit reached"));
    }
    let pairs: Vec<(String, String)> = r.items.into_iter().map(|i| (i.id, i.data)).collect();
    let (revision, _) = db::upsert_items(&mut db, &a.user_id, &pairs)?;
    Ok(Json(json!({ "revision": revision, "count": pairs.len() })))
}

pub async fn delete_item(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let a = authed!(st, headers, addr);
    validate_item_id(&id)?;
    let revision = db::delete_item(&mut st.db.lock().unwrap(), &a.user_id, &id)?;
    Ok(Json(json!({ "revision": revision })))
}

pub async fn sessions(State(st): State<Shared>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> ApiResult {
    let a = authed!(st, headers, addr);
    let list = db::list_sessions(&st.db.lock().unwrap(), &a.user_id, &a.session_id)?;
    Ok(Json(json!({ "sessions": list })))
}

pub async fn revoke_session(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(sid): Path<String>,
) -> ApiResult {
    let a = authed!(st, headers, addr);
    if !db::delete_session(&st.db.lock().unwrap(), &a.user_id, &sid)? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Session not found"));
    }
    Ok(Json(json!({ "ok": true })))
}

// ---------- admin helpers (CLI) ----------

pub fn create_invite(conn: &Connection, days: i64) -> anyhow::Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut raw = [0u8; 10];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let chars: String = raw.iter().map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char).collect();
    let code = format!("KH-{}-{}", &chars[..5], &chars[5..]);
    db::insert_invite(conn, &sha256_hex(code.as_bytes()), now_ms() + days * 24 * 3600 * 1000)?;
    Ok(code)
}

// ---------- website icons ----------

#[derive(Deserialize)]
pub struct IconQuery {
    host: String,
}

const ICON_TTL_OK: i64 = 14 * 24 * 3600 * 1000;
const ICON_TTL_MISS: i64 = 24 * 3600 * 1000;

fn icon_response(data: Vec<u8>, mime: &str) -> Response {
    let mut res = (StatusCode::OK, data).into_response();
    let h = res.headers_mut();
    h.insert("content-type", mime.parse().unwrap());
    h.insert("cache-control", "private, max-age=86400".parse().unwrap());
    h.insert("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox".parse().unwrap());
    res
}

/// GET /api/icon?host=example.com — the site's favicon, fetched and cached by this server.
pub async fn icon(
    State(st): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<IconQuery>,
) -> Result<Response, ApiError> {
    let a = authed!(st, headers, addr);
    let host = q.host.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    if !crate::icons::host_ok(&host) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Invalid host"));
    }
    if !crate::admin::load(&st.db.lock().unwrap()).icons_enabled {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Website icons are disabled on this server"));
    }
    let now = now_ms();
    let cached = db::get_icon(&st.db.lock().unwrap(), &host)?;
    if let Some(c) = &cached {
        let ttl = if c.data.is_some() { ICON_TTL_OK } else { ICON_TTL_MISS };
        if now - c.fetched_at < ttl {
            return match (&c.data, &c.mime) {
                (Some(d), Some(m)) => Ok(icon_response(d.clone(), m)),
                _ => Err(ApiError::new(StatusCode::NOT_FOUND, "No icon")),
            };
        }
    }
    let key = format!("icons:{}", a.user_id);
    st.limiter.check(&key, 300, Duration::from_secs(3600))?;
    st.limiter.fail(&key);
    let _slot = st.icon_slots.acquire().await.map_err(|e| ApiError::from(e.to_string()))?;
    use crate::icons::Lookup;
    match crate::icons::fetch_icon(&host).await {
        Lookup::Found(d, m) => {
            db::put_icon(&st.db.lock().unwrap(), &host, Some((d.as_slice(), m)))?;
            Ok(icon_response(d, m))
        }
        Lookup::Missing => {
            db::put_icon(&st.db.lock().unwrap(), &host, None)?;
            Err(ApiError::new(StatusCode::NOT_FOUND, "No icon"))
        }
        Lookup::Unreachable => Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Site unreachable, try again later")),
    }
}
