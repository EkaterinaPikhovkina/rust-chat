use argon2::{self, Config};
use futures_util::{SinkExt, StreamExt};
use rand::random;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tokio_postgres::{Client, NoTls};
use warp::http::StatusCode;
use warp::Filter;

#[derive(Deserialize)]
struct User {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Message {
    username: String,
    message: String,
}

// CREATE TABLE chat_history (
// id SERIAL PRIMARY KEY,
// username TEXT NOT NULL,
// message TEXT NOT NULL,
// timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
// );

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

impl From<postgres::Row> for Message {
    fn from(row: postgres::Row) -> Self {
        Self {
            username: row.get("username"),
            message: row.get("message"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client, connection) =
        tokio_postgres::connect("postgres://postgres:root@localhost:5432/postgres", NoTls)
            .await
            .unwrap();
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });
    let db_client = Arc::new(Mutex::new(client));

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
            let db_client = db_client.clone();
            ws.on_upgrade(move |websocket| handle_connection(websocket, tx, db_client))
        });

    let static_route = warp::path::end().and(warp::fs::file("index.html"));

    let routes = register.or(login).or(ws_route).or(static_route);
    println!("Server listening on 127.0.0.1:8080");

    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;

    Ok(())
}

async fn handle_connection(
    ws: warp::ws::WebSocket,
    tx: Arc<Mutex<broadcast::Sender<Message>>>,
    db_client: Arc<Mutex<Client>>,
) {
    let (mut ws_sender, mut ws_receiver) = ws.split();

    // Subscribe to the broadcast channel
    let mut rx = {
        let tx_guard = tx.lock().await;
        tx_guard.subscribe()
    };

    let db_client_clone_for_sender = db_client.clone(); // Клонируем для отправки исторических

    // Task to send broadcast messages to the client
    tokio::spawn(async move {
        let client = db_client_clone_for_sender.lock().await;
        // Отправка всех сохраненных сообщений клиенту при подключении
        if let Ok(rows) = client.query("SELECT username, message FROM chat_history", &[]).await {
            for row in rows {
                let msg = Message {
                    username: row.get("username"),
                    message: row.get("message"),
                };
                let json = serde_json::to_string(&msg).unwrap();
                if ws_sender.send(warp::ws::Message::text(json)).await.is_err() {
                    return;
                }
            }
        }
        drop(client); // Важно освободить MutexGuard

        while let Ok(msg) = rx.recv().await {
            let json = serde_json::to_string(&msg).unwrap();
            if ws_sender.send(warp::ws::Message::text(json)).await.is_err() {
                break;
            }
        }
    });

    // Process incoming messages
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(message) => {
                if let Ok(text) = message.to_str() {
                    // Разбираем JSON-строку
                    if let Ok(incoming) = serde_json::from_str::<Message>(text) {
                        let db_client_clone_for_insert = db_client.clone(); // Клонируем для вставки
                        let client = db_client_clone_for_insert.lock().await;
                        // Сохранение в базу данных
                        if let Err(e) = client
                            .execute(
                                "INSERT INTO chat_history (username, message) VALUES ($1, $2)",
                                &[&incoming.username, &incoming.message],
                            )
                            .await
                        {
                            eprintln!("Failed to save message: {}", e);
                        }
                        drop(client); // Важно освободить MutexGuard

                        // Объединяем в строку для отображения
                        let formatted_message =
                            format!("{}: {}", incoming.username, incoming.message);
                        println!("{}", formatted_message);

                        // Создаём сообщение для отправки остальным клиентам
                        let new_message = Message {
                            username: incoming.username.clone(),
                            message: incoming.message.clone(),
                        };

                        let tx_guard = tx.lock().await;
                        let _ = tx_guard.send(new_message);
                    } else {
                        eprintln!("Invalid JSON received: {}", text);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
                break;
            }
        }
    }
}
