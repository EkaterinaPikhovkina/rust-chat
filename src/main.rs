use argon2::{self, Config};
use futures_util::{SinkExt, StreamExt};
use rand::random;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use base64::Engine;
use tokio::sync::{broadcast, Mutex};
use tokio_postgres::{Client, Error as PgError, NoTls, Row};
use warp::ws::{Message as WarpMessage};
use warp::{
    Filter,
    http::header::{CONTENT_DISPOSITION, HeaderValue},
    hyper::Body,
    reply::{json, with_status, Response},
    Rejection,
    Reply,
    http::StatusCode,
};
use base64::engine::general_purpose;

#[derive(Deserialize)]
struct User {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    pub username: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_base64: Option<String>,
}

// -- Створення таблиці chat_history з вказаними колонками
// CREATE TABLE chat_history (
// user_id INTEGER REFERENCES users(id),  -- Зовнішній ключ, що посилається на таблицю users
// message TEXT,
// timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- Таймстамп з часовою зоною
// file BYTEA -- Тип даних BYTEA для зберігання файлів
// );

async fn register(
    new_user: User,
    db_client: Arc<Mutex<Client>>,
) -> Result<impl Reply, Rejection> {
    let client = db_client.lock().await;

    let existing_user = client
        .query_opt(
            "SELECT 1 FROM users WHERE username = $1",
            &[&new_user.username],
        )
        .await;
    if let Ok(Some(_)) = existing_user {
        return Ok(StatusCode::BAD_REQUEST);
    }

    let hashed_user = User {
        username: new_user.username,
        password: hash(new_user.password.as_bytes()),
    };

    match client
        .execute(
            "INSERT INTO users (username, password) VALUES ($1, $2)",
            &[&hashed_user.username.clone(), &hashed_user.password.clone()],
        )
        .await
    {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(e) => {
            eprintln!("Error inserting user: {:?}", e);
            Ok(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn login(
    credentials: User,
    db_client: Arc<Mutex<Client>>,
    auth: Arc<Mutex<HashMap<String, bool>>>,
) -> Result<impl Reply, Rejection> {
    let client = db_client.lock().await;

    let user_row = client
        .query_opt(
            "SELECT password FROM users WHERE username = $1",
            &[&credentials.username],
        )
        .await;

    match user_row {
        Ok(Some(row)) => {
            let db_password: String = row.get(0);
            if verify(&db_password, credentials.password.as_bytes()) {
                let mut sessions = auth.lock().await;
                sessions.insert(credentials.username.clone(), true);

                let response = json(&HashMap::from([("username", credentials.username)]));
                Ok(with_status(response, StatusCode::OK))
            } else {
                let error_response = json(&HashMap::from([("error", "Unauthorized")]));
                Ok(with_status(error_response, StatusCode::UNAUTHORIZED))
            }
        }
        Ok(None) => {
            let error_response = json(&HashMap::from([("error", "User not found")]));
            Ok(with_status(error_response, StatusCode::NOT_FOUND)) // 404 Not Found
        }
        Err(e) => {
            eprintln!("Error during login: {:?}", e);
            let error_response = json(&HashMap::from([("error", "Internal Server Error")]));
            Ok(with_status(
                error_response,
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
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

impl From<Row> for Message {
    fn from(row: Row) -> Self {
        Self {
            username: row.get("username"),
            message: row.get("message"),
            file: row.get("file"),
            filename: row.get("filename"),
            file_base64: row.get("file_base64"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
    let auth = Arc::new(Mutex::new(HashMap::new()));

    let db_client_register = db_client.clone();
    let db_client_login = db_client.clone();
    let db_client_ws = db_client.clone();

    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::json())
        .and(warp::any().map(move || db_client_register.clone()))
        .and_then(register);
    let login = warp::post()
        .and(warp::path("login"))
        .and(warp::body::json())
        .and(warp::any().map(move || db_client_login.clone()))
        .and(warp::any().map(move || auth.clone()))
        .and_then(login);

    let (tx, _rx) = broadcast::channel(100);
    let tx = Arc::new(Mutex::new(tx));
    let tx_ws = tx.clone();

    let get_file = warp::path!("files" / i32)
        .and(warp::any().map(move || db_client.clone()))
        .and_then(get_file_from_db);

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let tx = tx_ws.clone();
            let db_client = db_client_ws.clone();
            ws.on_upgrade(move |websocket| async move {
                if let Err(e) = handle_connection(websocket, tx, db_client).await {
                    eprintln!("Error in handle_connection: {}", e);
                }
            })
        });

    let static_route = warp::path::end().and(warp::fs::file("index.html"));

    let routes = register
        .or(login)
        .or(get_file)
        .or(ws_route)
        .or(static_route);
    println!("Server listening on 127.0.0.1:8080");

    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;

    Ok(())
}

async fn handle_connection(
    ws: warp::ws::WebSocket,
    tx: Arc<Mutex<broadcast::Sender<Message>>>,
    db_client: Arc<Mutex<Client>>,
) -> Result<(), PgError> {
    let (mut ws_sender, mut ws_receiver) = ws.split();

    let mut rx = {
        let tx_guard = tx.lock().await;
        tx_guard.subscribe()
    };

    let db_client_clone_for_sender = db_client.clone();

    tokio::spawn(async move {
        let client = db_client_clone_for_sender.lock().await;

        let query = "SELECT username, message, file, filename FROM chat_history";
        if let Ok(rows) = client.query(query, &[]).await {
            for row in rows {
                let msg = message_from_row(row);
                let json = serde_json::to_string(&msg).unwrap();
                if ws_sender.send(WarpMessage::text(json)).await.is_err() {
                    return;
                }
            }
        }
        drop(client);

        while let Ok(msg) = rx.recv().await {
            let json = serde_json::to_string(&msg).unwrap();
            if ws_sender.send(WarpMessage::text(json)).await.is_err() {
                break;
            }
        }
    });

    while let Some(result) = ws_receiver.next().await {
        let message = match result {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("WebSocket error: {}", e);
                break;
            }
        };

        if message.is_text() {
            let text = message.to_str().unwrap();
            let incoming: Message = match serde_json::from_str(text) {
                Ok(msg) => msg,
                Err(e) => {
                    eprintln!("Invalid JSON received: {}. Error: {}", text, e);
                    continue;
                }
            };

            let file_data = incoming.file_base64.as_ref().map(|base64_string| {
                general_purpose::STANDARD.decode(base64_string).unwrap()
            });

            let db_client_clone = db_client.clone();
            let client = db_client_clone.lock().await;

            let statement = client.prepare("INSERT INTO chat_history (username, message, file, filename) VALUES ($1, $2, $3, $4)").await?;
            if let Err(e) = client
                .execute(
                    &statement,
                    &[
                        &incoming.username,
                        &incoming.message,
                        &file_data,
                        &incoming.filename,
                    ],
                )
                .await
            {
                eprintln!("Failed to save message: {}", e);
            }

            let new_message = Message {
                username: incoming.username,
                message: incoming.message,
                file: file_data,
                filename: incoming.filename,
                file_base64: None,
            };

            let tx_guard = tx.lock().await;

            if let Err(e) = tx_guard.send(new_message) {
                eprintln!("failed to send message to broadcast channel: {}", e);
            }
        } else if message.is_close() {
            break;
        }
    }
    Ok(())
}

fn message_from_row(row: Row) -> Message {
    let file_data: Option<Vec<u8>> = row.try_get("file").ok();
    let file_base64 = file_data.as_ref().map(|data| general_purpose::STANDARD.encode(data));
    Message {
        username: row.get("username"),
        message: row.get("message"),
        file: file_data,
        filename: row.try_get("filename").ok(),
        file_base64,
    }
}

async fn get_file_from_db(
    file_id: i32,
    db_client: Arc<Mutex<Client>>,
) -> Result<impl Reply, Rejection> {
    let client = db_client.lock().await;
    let query = "SELECT file, filename FROM chat_history WHERE id = $1";

    let result = client.query_opt(query, &[&file_id]).await;
    match result {
        Ok(Some(row)) => {
            let file_data: Option<Vec<u8>> = row.try_get("file").ok();
            let filename: Option<String> = row.try_get("filename").ok();

            if let (Some(data), Some(filename)) = (file_data, filename) {
                let base64_data = general_purpose::STANDARD.encode(data);
                let body = Body::from(base64_data);
                let mut response = Response::new(body);
                response
                    .headers_mut()
                    .insert(
                        CONTENT_DISPOSITION,
                        HeaderValue::from_str(&format!(
                            "attachment; filename=\"{}\"",
                            filename
                        ))
                            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
                    );
                response.headers_mut().insert("Content-Type", "application/octet-stream".parse().unwrap());
                Ok(response)
            } else {
                println!("File data or filename is NULL for id: {}", file_id);
                Ok(Response::new(Body::from("None")))
            }
        }
        Ok(None) => {
            eprintln!("File not found with id: {}", file_id);
            Ok(Response::new(Body::from("None")))
        }
        Err(e) => {
            eprintln!("Database error fetching file: {}", e);
            Ok(Response::new(Body::from("None")))
        }
    }
}