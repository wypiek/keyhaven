//! SQLite storage. The server only ever stores ciphertext produced by clients, plus
//! the minimum metadata needed for sync (ids, revisions, timestamps).

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::Path;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn open(dir: &Path) -> Result<Connection> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let conn = Connection::open(dir.join("keyhaven.db"))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            kdf TEXT NOT NULL,
            auth_hash TEXT NOT NULL,
            wrapped_key TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS items (
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            id TEXT NOT NULL,
            data TEXT,
            revision INTEGER NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, id)
        );
        CREATE INDEX IF NOT EXISTS items_by_rev ON items(user_id, revision);
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            device TEXT NOT NULL,
            ip TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS icons (
            host TEXT PRIMARY KEY,
            data BLOB,
            mime TEXT,
            fetched_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invites (
            code_hash TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used_by TEXT
        );
        "#,
    )?;
    migrate(&conn)?;
    Ok(conn)
}

/// Schema upgrades for databases created by older versions.
fn migrate(c: &Connection) -> Result<()> {
    let has_role: bool = c
        .prepare("SELECT 1 FROM pragma_table_info('users') WHERE name = 'role'")?
        .exists([])?;
    if !has_role {
        c.execute_batch("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")?;
    }
    // Every instance with accounts needs at least one admin: promote the oldest account.
    let admins: i64 = c.query_row("SELECT COUNT(*) FROM users WHERE role = 'admin'", [], |r| r.get(0))?;
    if admins == 0 {
        c.execute(
            "UPDATE users SET role = 'admin' WHERE id = (SELECT id FROM users ORDER BY created_at LIMIT 1)",
            [],
        )?;
    }
    Ok(())
}

/// Per-server random secret (used for anti-enumeration fake salts). Created on first run.
pub fn server_secret(conn: &Connection) -> Result<[u8; 32]> {
    let existing: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key = 'secret'", [], |r| r.get(0))
        .optional()?;
    let b64 = match existing {
        Some(v) => v,
        None => {
            let mut s = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut s);
            let v = B64.encode(s);
            conn.execute("INSERT INTO meta (key, value) VALUES ('secret', ?1)", [&v])?;
            v
        }
    };
    let raw = B64.decode(b64)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw[..32]);
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub kdf: String,
    pub auth_hash: String,
    pub wrapped_key: String,
    pub revision: i64,
    pub created_at: i64,
    pub role: String,
}

fn map_user(r: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        email: r.get(1)?,
        kdf: r.get(2)?,
        auth_hash: r.get(3)?,
        wrapped_key: r.get(4)?,
        revision: r.get(5)?,
        created_at: r.get(6)?,
        role: r.get(7)?,
    })
}

const USER_COLS: &str = "id, email, kdf, auth_hash, wrapped_key, revision, created_at, role";

pub fn user_by_email(c: &Connection, email: &str) -> Result<Option<User>> {
    Ok(c.query_row(
        &format!("SELECT {USER_COLS} FROM users WHERE email = ?1"),
        [email],
        map_user,
    )
    .optional()?)
}

pub fn user_by_id(c: &Connection, id: &str) -> Result<Option<User>> {
    Ok(c.query_row(
        &format!("SELECT {USER_COLS} FROM users WHERE id = ?1"),
        [id],
        map_user,
    )
    .optional()?)
}

pub fn user_count(c: &Connection) -> Result<i64> {
    Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)
}

pub fn list_users(c: &Connection) -> Result<Vec<(String, i64, i64)>> {
    let mut st = c.prepare(
        "SELECT u.email, u.created_at, (SELECT COUNT(*) FROM items i WHERE i.user_id = u.id AND i.deleted = 0)
         FROM users u ORDER BY u.created_at",
    )?;
    let rows = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn insert_user(c: &Connection, u: &User) -> Result<()> {
    let now = now_ms();
    c.execute(
        "INSERT INTO users (id, email, kdf, auth_hash, wrapped_key, revision, created_at, updated_at, role)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6, ?7)",
        params![u.id, u.email, u.kdf, u.auth_hash, u.wrapped_key, now, u.role],
    )?;
    Ok(())
}

pub fn update_credentials(c: &Connection, user_id: &str, kdf: &str, auth_hash: &str, wrapped_key: &str) -> Result<()> {
    c.execute(
        "UPDATE users SET kdf = ?2, auth_hash = ?3, wrapped_key = ?4, updated_at = ?5 WHERE id = ?1",
        params![user_id, kdf, auth_hash, wrapped_key, now_ms()],
    )?;
    Ok(())
}

pub fn delete_user(c: &Connection, user_id: &str) -> Result<()> {
    c.execute("DELETE FROM users WHERE id = ?1", [user_id])?;
    Ok(())
}

// ---------- sessions ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub device: String,
    pub ip: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub current: bool,
}

pub const SESSION_TTL_MS: i64 = 30 * 24 * 3600 * 1000;

pub fn insert_session(c: &Connection, id: &str, user_id: &str, token_hash: &str, device: &str, ip: &str) -> Result<()> {
    let now = now_ms();
    c.execute("DELETE FROM sessions WHERE expires_at < ?1", [now])?;
    c.execute(
        "INSERT INTO sessions (id, user_id, token_hash, device, ip, created_at, last_used_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
        params![id, user_id, token_hash, device, ip, now, now + SESSION_TTL_MS],
    )?;
    Ok(())
}

/// Resolve a bearer token to (session id, user id); slides the expiry window.
pub fn touch_session(c: &Connection, token_hash: &str, ip: &str) -> Result<Option<(String, String)>> {
    let now = now_ms();
    let row: Option<(String, String)> = c
        .query_row(
            "SELECT id, user_id FROM sessions WHERE token_hash = ?1 AND expires_at > ?2",
            params![token_hash, now],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((sid, _)) = &row {
        c.execute(
            "UPDATE sessions SET last_used_at = ?2, expires_at = ?3, ip = ?4 WHERE id = ?1",
            params![sid, now, now + SESSION_TTL_MS, ip],
        )?;
    }
    Ok(row)
}

pub fn list_sessions(c: &Connection, user_id: &str, current: &str) -> Result<Vec<SessionInfo>> {
    let mut st = c.prepare(
        "SELECT id, device, ip, created_at, last_used_at FROM sessions
         WHERE user_id = ?1 AND expires_at > ?2 ORDER BY last_used_at DESC",
    )?;
    let rows = st
        .query_map(params![user_id, now_ms()], |r| {
            let id: String = r.get(0)?;
            Ok(SessionInfo {
                current: id == current,
                id,
                device: r.get(1)?,
                ip: r.get(2)?,
                created_at: r.get(3)?,
                last_used_at: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn delete_session(c: &Connection, user_id: &str, sid: &str) -> Result<bool> {
    Ok(c.execute("DELETE FROM sessions WHERE id = ?1 AND user_id = ?2", [sid, user_id])? > 0)
}

pub fn delete_other_sessions(c: &Connection, user_id: &str, keep: &str) -> Result<()> {
    c.execute("DELETE FROM sessions WHERE user_id = ?1 AND id != ?2", [user_id, keep])?;
    Ok(())
}

// ---------- items ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemRow {
    pub id: String,
    pub data: Option<String>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: i64,
}

pub fn items_since(c: &Connection, user_id: &str, since: i64) -> Result<Vec<ItemRow>> {
    let mut st = c.prepare(
        "SELECT id, data, revision, deleted, updated_at FROM items
         WHERE user_id = ?1 AND revision > ?2 AND (deleted = 0 OR ?2 > 0) ORDER BY revision",
    )?;
    let rows = st
        .query_map(params![user_id, since], |r| {
            Ok(ItemRow {
                id: r.get(0)?,
                data: r.get(1)?,
                revision: r.get(2)?,
                deleted: r.get::<_, i64>(3)? != 0,
                updated_at: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn item_count(c: &Connection, user_id: &str) -> Result<i64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM items WHERE user_id = ?1 AND deleted = 0",
        [user_id],
        |r| r.get(0),
    )?)
}

fn bump_revision(c: &Connection, user_id: &str) -> Result<i64> {
    Ok(c.query_row(
        "UPDATE users SET revision = revision + 1 WHERE id = ?1 RETURNING revision",
        [user_id],
        |r| r.get(0),
    )?)
}

pub fn current_revision(c: &Connection, user_id: &str) -> Result<i64> {
    Ok(c.query_row("SELECT revision FROM users WHERE id = ?1", [user_id], |r| r.get(0))?)
}

/// Insert or replace items in one transaction; every item gets its own new revision.
pub fn upsert_items(c: &mut Connection, user_id: &str, items: &[(String, String)]) -> Result<(i64, i64)> {
    let tx = c.transaction()?;
    let now = now_ms();
    let mut rev = 0;
    for (id, data) in items {
        rev = bump_revision(&tx, user_id)?;
        tx.execute(
            "INSERT INTO items (user_id, id, data, revision, deleted, updated_at) VALUES (?1, ?2, ?3, ?4, 0, ?5)
             ON CONFLICT(user_id, id) DO UPDATE SET data = excluded.data, revision = excluded.revision,
               deleted = 0, updated_at = excluded.updated_at",
            params![user_id, id, data, rev, now],
        )?;
    }
    tx.commit()?;
    Ok((rev, now))
}

/// Permanently delete an item, leaving a tombstone so other devices learn about it.
pub fn delete_item(c: &mut Connection, user_id: &str, id: &str) -> Result<i64> {
    let tx = c.transaction()?;
    let rev = bump_revision(&tx, user_id)?;
    tx.execute(
        "INSERT INTO items (user_id, id, data, revision, deleted, updated_at) VALUES (?1, ?2, NULL, ?3, 1, ?4)
         ON CONFLICT(user_id, id) DO UPDATE SET data = NULL, revision = excluded.revision, deleted = 1,
           updated_at = excluded.updated_at",
        params![user_id, id, rev, now_ms()],
    )?;
    tx.commit()?;
    Ok(rev)
}

// ---------- invites ----------

pub fn insert_invite(c: &Connection, code_hash: &str, expires_at: i64) -> Result<()> {
    c.execute(
        "INSERT INTO invites (code_hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
        params![code_hash, now_ms(), expires_at],
    )?;
    Ok(())
}

/// Atomically consume an invite. Returns false if unknown, used or expired.
pub fn consume_invite(c: &Connection, code_hash: &str, email: &str) -> Result<bool> {
    Ok(c.execute(
        "UPDATE invites SET used_by = ?2 WHERE code_hash = ?1 AND used_by IS NULL AND expires_at > ?3",
        params![code_hash, email, now_ms()],
    )? > 0)
}

// ---------- icon cache ----------

pub struct CachedIcon {
    pub data: Option<Vec<u8>>,
    pub mime: Option<String>,
    pub fetched_at: i64,
}

pub fn get_icon(c: &Connection, host: &str) -> Result<Option<CachedIcon>> {
    Ok(c.query_row("SELECT data, mime, fetched_at FROM icons WHERE host = ?1", [host], |r| {
        Ok(CachedIcon { data: r.get(0)?, mime: r.get(1)?, fetched_at: r.get(2)? })
    })
    .optional()?)
}

pub fn put_icon(c: &Connection, host: &str, icon: Option<(&[u8], &str)>) -> Result<()> {
    c.execute(
        "INSERT INTO icons (host, data, mime, fetched_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(host) DO UPDATE SET data = excluded.data, mime = excluded.mime, fetched_at = excluded.fetched_at",
        params![host, icon.map(|i| i.0), icon.map(|i| i.1), now_ms()],
    )?;
    Ok(())
}

// ---------- admin ----------

pub fn set_role(c: &Connection, user_id: &str, role: &str) -> Result<()> {
    c.execute("UPDATE users SET role = ?2, updated_at = ?3 WHERE id = ?1", params![user_id, role, now_ms()])?;
    Ok(())
}

pub fn admin_count(c: &Connection) -> Result<i64> {
    Ok(c.query_row("SELECT COUNT(*) FROM users WHERE role = 'admin'", [], |r| r.get(0))?)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUser {
    pub id: String,
    pub email: String,
    pub role: String,
    pub created_at: i64,
    pub items: i64,
    pub sessions: i64,
    pub last_active: Option<i64>,
}

pub fn admin_users(c: &Connection) -> Result<Vec<AdminUser>> {
    let mut st = c.prepare(
        "SELECT u.id, u.email, u.role, u.created_at,
           (SELECT COUNT(*) FROM items i WHERE i.user_id = u.id AND i.deleted = 0),
           (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > ?1),
           (SELECT MAX(last_used_at) FROM sessions s WHERE s.user_id = u.id)
         FROM users u ORDER BY u.created_at",
    )?;
    let rows = st
        .query_map([now_ms()], |r| {
            Ok(AdminUser {
                id: r.get(0)?,
                email: r.get(1)?,
                role: r.get(2)?,
                created_at: r.get(3)?,
                items: r.get(4)?,
                sessions: r.get(5)?,
                last_active: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn delete_user_sessions(c: &Connection, user_id: &str) -> Result<usize> {
    Ok(c.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?)
}

pub fn total_items(c: &Connection) -> Result<i64> {
    Ok(c.query_row("SELECT COUNT(*) FROM items WHERE deleted = 0", [], |r| r.get(0))?)
}

pub fn db_bytes(c: &Connection) -> Result<i64> {
    Ok(c.query_row("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()", [], |r| r.get(0))?)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteInfo {
    pub id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_by: Option<String>,
}

pub fn list_invites(c: &Connection) -> Result<Vec<InviteInfo>> {
    let mut st = c.prepare("SELECT code_hash, created_at, expires_at, used_by FROM invites ORDER BY created_at DESC LIMIT 200")?;
    let rows = st
        .query_map([], |r| {
            let h: String = r.get(0)?;
            Ok(InviteInfo { id: h[..16].to_string(), created_at: r.get(1)?, expires_at: r.get(2)?, used_by: r.get(3)? })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn delete_invite(c: &Connection, id_prefix: &str) -> Result<bool> {
    if id_prefix.len() != 16 || !id_prefix.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(false);
    }
    Ok(c.execute("DELETE FROM invites WHERE substr(code_hash, 1, 16) = ?1", [id_prefix])? > 0)
}

pub fn get_meta(c: &Connection, key: &str) -> Result<Option<String>> {
    Ok(c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
}

pub fn set_meta(c: &Connection, key: &str, value: &str) -> Result<()> {
    c.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}
