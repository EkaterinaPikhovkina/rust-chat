use futures_util::{StreamExt, SinkExt};
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use warp::Filter;
use std::collections::HashMap;
use serde::Deserialize;
use warp::http::StatusCode;
use argon2::{self, Config};
use rand::random;
use tokio_postgres::{NoTls, Error};

#[derive(Deserialize)]
struct User {
    username: String,
    password: String,
}

async fn register(
    new_user: User,
    db: Arc<Mutex<HashMap<String, User>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let mut users = db.lock().await;
    if users.contains_key(&new_user.username) {
        return Ok(StatusCode::BAD_REQUEST);
    }
    let hashed_user = User {
        username: new_user.username,
        password: hash(new_user.password.as_bytes()),
    };
    users.insert(hashed_user.username.clone(), hashed_user);
    Ok(StatusCode::CREATED)
}

async fn login(
    credentials: User,
    db: Arc<Mutex<HashMap<String, User>>>,
    auth: Arc<Mutex<HashMap<String, bool>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let users = db.lock().await;
    match users.get(&credentials.username) {
        None => Ok(StatusCode::BAD_REQUEST),
        Some(user) => {
            if verify(&user.password, credentials.password.as_bytes()) {
                let mut sessions = auth.lock().await;
                sessions.insert(credentials.username.clone(), true);
                Ok(StatusCode::OK)
            } else {
                Ok(StatusCode::UNAUTHORIZED)
            }
        }
    }
}

pub fn hash(password: &[u8]) -> String {
    let salt = random::<[u8; 32]>();
    let config = Config::default();
    argon2::hash_encoded(password, &salt, &config).unwrap()
}

pub fn verify(hash: &str, password: &[u8]) -> bool {
    argon2::verify_encoded(hash, password).unwrap_or(false)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client, connection) = tokio_postgres::connect("postgres://postgres:root@localhost:5432/postgres", NoTls).await?;
    tokio::spawn(connection); // Запускаем соединение в фоновом режиме

    println!("Connected to PostgreSQL");

    let db = Arc::new(Mutex::new(HashMap::<String, User>::new()));
    let db = warp::any().map(move || Arc::clone(&db));

    let auth = Arc::new(Mutex::new(HashMap::<String, bool>::new()));
    let auth = warp::any().map(move || Arc::clone(&auth));

    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::json())
        .and(db.clone())
        .and_then(register);
    let login = warp::post()
        .and(warp::path("login"))
        .and(warp::body::json())
        .and(db.clone())
        .and(auth.clone())
        .and_then(login);

    let (tx, _rx) = broadcast::channel(100);
    let tx = Arc::new(Mutex::new(tx));
    let tx_ws = tx.clone();

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let tx = tx_ws.clone();
            ws.on_upgrade(move |websocket| handle_connection(websocket, tx))
        });

    let static_route = warp::path::end()
        .and(warp::fs::file("index.html"));

    let routes = register.or(login).or(ws_route).or(static_route);
    println!("Server listening on 127.0.0.1:8080");

    warp::serve(routes)
        .run(([127, 0, 0, 1], 8080))
        .await;

    Ok(())
}

async fn handle_connection(
    ws: warp::ws::WebSocket,
    tx: Arc<Mutex<broadcast::Sender<String>>>,
) {
    let (mut ws_sender, mut ws_receiver) = ws.split();
    // Subscribe to the broadcast channel
    let mut rx = {
        let tx_guard = tx.lock().await; // Use .await to get the MutexGuard
        tx_guard.subscribe()
    };
    // Task to send broadcast messages to the client
    tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if ws_sender.send(warp::ws::Message::text(msg)).await.is_err() {
                break;
            }
        }
    });
    // Process incoming messages
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(message) => {
                if let Ok(text) = message.to_str() {
                    println!("Received message: {}", text);

                    let tx_guard = tx.lock().await;
                    let _ = tx_guard.send(text.to_string());
                }
            },
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
                break;
            }
        }
    }
}