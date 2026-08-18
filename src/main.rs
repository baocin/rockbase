// rockbase binary — reads env, opens the database, serves the app.

use rusqlite::Connection;

#[tokio::main]
async fn main() {
    std::fs::create_dir_all("rb_data").expect("create rb_data");
    let conn = Connection::open("rb_data/data.db").expect("open db");
    let admin_token = std::env::var("RB_ADMIN_TOKEN")
        .unwrap_or_else(|_| uuid::Uuid::new_v4().simple().to_string());
    println!("admin token: {admin_token}");
    println!("rockbase on http://127.0.0.1:8090");
    let router = rockbase::build_app(conn, admin_token);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8090")
        .await
        .expect("bind 8090");
    axum::serve(listener, router).await.expect("serve");
}
