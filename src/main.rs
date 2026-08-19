// rockbase binary — reads env, opens the database, serves the app.

/// Env config. A typo'd port must fail loudly, not silently become 8090.
fn env_config() -> (u16, std::path::PathBuf) {
    let port = match std::env::var("RB_PORT") {
        Ok(v) => v
            .parse()
            .unwrap_or_else(|e| panic!("RB_PORT must be a valid port number, got {v:?}: {e}")),
        Err(_) => 8090,
    };
    let dir = std::env::var("RB_DIR").unwrap_or_else(|_| "rb_data".into());
    (port, dir.into())
}

#[tokio::main]
async fn main() {
    let (port, dir) = env_config();
    std::fs::create_dir_all(&dir).expect("create data dir");
    let db = dir.join("data.db");
    let db = db.to_str().expect("data dir path must be UTF-8");
    let admin_token = std::env::var("RB_ADMIN_TOKEN")
        .unwrap_or_else(|_| uuid::Uuid::new_v4().simple().to_string());
    println!("admin token: {admin_token}");
    // The pool opens (and so creates data.db) before the banner: `tests/cli.rs` treats
    // "rockbase on ..." as the signal that the data dir is on disk, and `tests/ops.rs`
    // treats it as the signal that binding is imminent. Both hold only in this order.
    let router = rockbase::build_app(db, admin_token);
    println!("rockbase on http://127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("bind 127.0.0.1:{port}: {e}"));
    axum::serve(listener, router).await.expect("serve");
}
