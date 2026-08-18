// Admin-only backup: VACUUM INTO a temp file, serve the bytes, delete the file.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::Value;

use crate::auth::require_admin;
use crate::{err, S};

// ponytail: one-shot download, not PocketBase's list/create/download trio;
// split when someone needs stored backups.
pub async fn backup_download(
    State(app): State<S>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    require_admin(&app, &headers)?;
    // Unique name because VACUUM INTO fails if the target exists.
    let tmp = std::env::temp_dir().join(format!(
        "rockbase_backup_{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let tmp_str = tmp
        .to_str()
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad temp path"))?
        .to_string();
    {
        let db = app.db.lock().unwrap();
        // VACUUM INTO writes a compacted, consistent copy; works from
        // in-memory DBs too (SQLite >= 3.27). Path binds as a parameter.
        db.execute("VACUUM INTO ?1", [&tmp_str]).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;
    } // lock released before file IO
    // ponytail: full read into RAM; stream the file if backups outgrow memory.
    let bytes = std::fs::read(&tmp).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;
    let _ = std::fs::remove_file(&tmp);
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"rockbase_{ts}.db\""),
            ),
        ],
        bytes,
    ))
}
