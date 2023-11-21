use {
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
    std::sync::{Arc, Mutex},
    url::Url,
};

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use {
    futures_util::{stream::SplitSink, SinkExt, StreamExt},
    http::Request,
    reqwest_cookie_store::{CookieStore, CookieStoreMutex},
    std::mem::replace,
    std::ops::DerefMut,
    tokio::{net::TcpStream, select, sync::oneshot},
    tokio_tungstenite::{connect_async, tungstenite::protocol::Message},
};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use {
    wasm_bindgen::{closure::Closure, JsCast},
    wasm_bindgen_futures::JsFuture,
    web_sys::{Request, RequestCredentials, RequestInit, RequestMode, Response, WebSocket},
    yew::platform::pinned::oneshot,
};

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
macro_rules! log {
    ( $( $t:tt )* ) => {
        println!( $( $t )* );
    }
}

// A macro to provide `println!(..)`-style syntax for `console.log` logging.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

fn get_env_var_url(env_name: &str, option_env: Option<&'static str>, default: &str) -> Url {
    Url::parse(match std::env::var(env_name).as_ref() {
        Ok(value) => value.as_str(),
        Err(_) => option_env.unwrap_or(default),
    })
    .unwrap()
}

pub fn get_root_domain() -> Url {
    get_env_var_url(
        "UNET_ROOT_DOMAIN",
        option_env!("UNET_ROOT_DOMAIN"),
        "https://unet.tech",
    )
}

pub fn get_api_domain() -> Url {
    get_env_var_url(
        "UNET_API_DOMAIN",
        option_env!("UNET_API_DOMAIN"),
        "https://api.unet.tech",
    )
}

pub fn get_websocket_domain() -> Url {
    get_env_var_url(
        "UNET_WEBSOCKET_DOMAIN",
        option_env!("UNET_WEBSOCKET_DOMAIN"),
        "wss://wss.api.unet.tech",
    )
}

pub fn get_stack_id() -> String {
    match std::env::var("UNET_STACK_ID") {
        Ok(stack_id) => stack_id,
        Err(_) => option_env!("UNET_STACK_ID").unwrap_or("prod").to_string(),
    }
}

pub fn get_stack_name() -> String {
    format!("unet-dev-{}", get_stack_id())
}

pub fn get_hosted_zone_id() -> String {
    match std::env::var("UNET_HOSTED_ZONE_ID") {
        Ok(hosted_zone_id) => hosted_zone_id,
        Err(_) => option_env!("UNET_HOSTED_ZONE_ID")
            .unwrap_or("Z05848283TO5CBMZHZTRN")
            .to_string(),
    }
}

pub fn get_auth_domain() -> Url {
    let auth_domain = match std::env::var("UNET_AUTH_DOMAIN") {
        Ok(auth_domain) => auth_domain,
        Err(_) => option_env!("UNET_AUTH_DOMAIN")
            .unwrap_or("https://auth.unet.tech")
            .to_string(),
    };

    Url::parse(auth_domain.as_str()).unwrap()
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "tag", content = "content")]
pub enum WebsocketClientMessage {
    LoginRequest {},
    Request {
        request_id: String,
        request: WebsocketClientRequest,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WebsocketClientRequest {
    GetUser,
    GetPresignedUrl { object_path: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Credentials {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "tag", content = "content")]
pub enum WebsocketServerMessage {
    LoginUrl {
        url: String,
    },
    AuthCodeUrl {
        url: String,
    },
    Response {
        request_id: String,
        response: WebsocketServerResponse,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub user_id: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WebsocketServerError {
    Unauthorized,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WebsocketServerResponse {
    GetUser { user: User },
    GetPresignedUrl { url: String },
    Error { error: WebsocketServerError },
}

pub enum GetCredentialsError {
    NoCredentials,
    InvalidCredentials,
}

/// Load cookies from the cookie store
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn get_cookies() -> std::sync::Arc<CookieStoreMutex> {
    let mut cookies_path = dirs::config_dir().unwrap();
    cookies_path.push("unet");
    cookies_path.push("cookies.json");

    let cookie_store =
        if let Ok(file) = std::fs::File::open(cookies_path).map(std::io::BufReader::new) {
            if let Ok(cookie_store) = CookieStore::load_json(file) {
                cookie_store
            } else {
                CookieStore::new(None)
            }
        } else {
            CookieStore::new(None)
        };

    std::sync::Arc::new(CookieStoreMutex::new(cookie_store))
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
type WebSocketStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn establish_websocket_connection(cookies: &CookieStoreMutex) -> WebSocketStream {
    let websocket_domain = get_websocket_domain();

    let request_builder = Request::builder()
        .uri(websocket_domain.as_str())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("Sec-WebSocket-Version", "13")
        .header("Host", websocket_domain.host_str().unwrap())
        .header(
            "Cookie",
            cookies
                .lock()
                .unwrap()
                .iter_unexpired()
                .map(|cookie| {
                    format!(
                        "{}={}",
                        cookie.name().to_string(),
                        cookie.value().to_string()
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        );
    // let request_builder = match get_credentials().await {
    //     Ok(credentials) => request_builder.header(
    //         "Authorization",
    //         format!("Bearer {}", credentials.access_token),
    //     ),
    //     Err(_) => request_builder,
    // }

    let request = request_builder.body(()).unwrap();

    let (ws_stream, _) = connect_async(request).await.unwrap();

    ws_stream
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[derive(Debug)]
struct ClientConnection {
    ws: WebSocket,
    #[allow(dead_code)] // Needed to keep the callback alive
    on_message_callback: Mutex<Option<Closure<dyn FnMut(web_sys::MessageEvent)>>>,
    response_map: Mutex<HashMap<String, oneshot::Sender<WebsocketServerResponse>>>,
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
async fn connect() -> Result<Arc<ClientConnection>, ConnectError> {
    // Post to /auth/refresh
    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.credentials(RequestCredentials::Include);

    let request = Request::new_with_str_and_init(
        {
            let api_domain = get_api_domain();
            api_domain.join("/auth/refresh").unwrap().as_str()
        },
        &opts,
    )
    .unwrap();

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .unwrap();

    assert!(resp_value.is_instance_of::<Response>());

    // Convert this other `Promise` into a rust `Future`.
    let json = JsFuture::from(resp_value.dyn_into::<Response>().unwrap().json().unwrap())
        .await
        .unwrap();

    let ws = WebSocket::new(get_websocket_domain().as_str()).unwrap();

    // Just for maintaining ownership of the callbacks during the call so they
    // don't get dropped.
    let mut connect_callbacks = (None, None);

    let connect_promise = js_sys::Promise::new(&mut |resolve, _| {
        let on_open_callback = Closure::wrap(Box::new(move || {
            resolve.call0(&wasm_bindgen::JsValue::null()).unwrap();
        }) as Box<dyn FnMut()>);

        ws.set_onopen(Some(on_open_callback.as_ref().unchecked_ref()));

        let on_close_callback = Closure::wrap(Box::new(move || {
            log!("WebSocket connection error");
        }) as Box<dyn FnMut()>);

        ws.set_onerror(Some(on_close_callback.as_ref().unchecked_ref()));

        connect_callbacks = (Some(on_open_callback), Some(on_close_callback));
    });

    wasm_bindgen_futures::JsFuture::from(connect_promise)
        .await
        .unwrap();

    ws.set_onopen(None);
    ws.set_onerror(None);

    let connection = Arc::new(ClientConnection {
        ws,
        on_message_callback: Mutex::new(None),
        response_map: HashMap::new().into(),
    });

    let on_message_callback_connection = Arc::clone(&connection);

    // set the on message callback
    let on_message_callback = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
        let data = event.data();

        if let Some(message) = data.as_string() {
            handle_client_message(&on_message_callback_connection, &message);
        } else {
            log!("Received data: {:?}", data);
        }
    }) as Box<dyn FnMut(_)>);

    connection
        .ws
        .set_onmessage(Some(on_message_callback.as_ref().unchecked_ref()));
    connection
        .on_message_callback
        .lock()
        .unwrap()
        .replace(on_message_callback);

    Ok(connection)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[derive(Debug)]
struct ClientConnection {
    write: tokio::sync::Mutex<SplitSink<WebSocketStream, Message>>,
    stop_signal_tx: Mutex<Option<oneshot::Sender<()>>>,
    process_messages: Mutex<Option<tokio::task::JoinHandle<()>>>,
    response_map: Mutex<HashMap<String, oneshot::Sender<WebsocketServerResponse>>>,
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn signal_close(connection: &ClientConnection) -> Option<tokio::task::JoinHandle<()>> {
    if let Some(close_tx) = replace(connection.stop_signal_tx.lock().unwrap().deref_mut(), None) {
        close_tx.send(()).unwrap();
        replace(
            connection.process_messages.lock().unwrap().deref_mut(),
            None,
        )
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn close_client_connection(connection: &ClientConnection) {
    if let Some(process_messages) = signal_close(connection) {
        connection.write.lock().await.close().await.unwrap();
        process_messages.await.unwrap();
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn write_to_client_connection(
    connection: &ClientConnection,
    message: &WebsocketClientMessage,
) {
    connection
        .write
        .lock()
        .await
        .send(Message::Text(serde_json::to_string(message).unwrap()))
        .await
        .unwrap();
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn make_call(
    connection: &ClientConnection,
    request: WebsocketClientRequest,
) -> WebsocketServerResponse {
    // Make a one-shot channel for the response
    let (response_tx, response_rx) = oneshot::channel::<WebsocketServerResponse>();

    // Generate a request ID
    let request_id = "abc".to_string(); // TODO

    // Store the response channel in the response map
    connection
        .response_map
        .lock()
        .unwrap()
        .insert(request_id.clone(), response_tx);

    write_to_client_connection(
        connection,
        &WebsocketClientMessage::Request {
            request_id,
            request,
        },
    )
    .await;

    // Wait for the response
    response_rx.await.unwrap()
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
async fn make_call(
    connection: &ClientConnection,
    request: WebsocketClientRequest,
) -> WebsocketServerResponse {
    let (response_tx, response_rx) =
        yew::platform::pinned::oneshot::channel::<WebsocketServerResponse>();

    let request_id = "abc"; // TOOD

    connection
        .response_map
        .lock()
        .unwrap()
        .insert(request_id.to_string(), response_tx);

    connection
        .ws
        .send_with_str(
            &serde_json::to_string(&WebsocketClientMessage::Request {
                request_id: request_id.to_string(),
                request,
            })
            .unwrap(),
        )
        .unwrap();

    response_rx.await.unwrap()
}

async fn get_user(connection: &ClientConnection) -> Result<User, WebsocketServerError> {
    let response = make_call(connection, WebsocketClientRequest::GetUser).await;
    match response {
        WebsocketServerResponse::GetUser { user } => Ok(user),
        WebsocketServerResponse::Error { error } => Err(error),
        _ => panic!("Unexpected response: {:?}", response),
    }
}

// #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
// async fn handle_client_message(connection: &ClientConnection, message: &str) {
//     // Decode the message as a WebsocketServerMessage
//     let message: WebsocketServerMessage = serde_json::from_str(message).unwrap();

//     match message {
//         WebsocketServerMessage::LoginUrl { .. } => {
//             println!("unexpected login URL");
//         }
//         WebsocketServerMessage::AuthCodeUrl { .. } => {
//             println!("unexpected auth code");
//         }
//         WebsocketServerMessage::Response {
//             request_id,
//             response,
//         } => {
//             // Get the response channel from the response map
//             if let Some(response_tx) = connection.response_map.lock().unwrap().remove(&request_id) {
//                 // Send the response
//                 response_tx.send(response).unwrap();
//             } else {
//                 panic!("Received response for unknown request ID: {}", request_id);
//             }
//         }
//     };
// }

fn handle_client_message(connection: &ClientConnection, message: &str) {
    // Decode the message as a WebsocketServerMessage
    let message: WebsocketServerMessage = serde_json::from_str(message).unwrap();

    match message {
        WebsocketServerMessage::LoginUrl { .. } => {
            println!("unexpected login URL");
        }
        WebsocketServerMessage::AuthCodeUrl { .. } => {
            println!("unexpected auth code");
        }
        WebsocketServerMessage::Response {
            request_id,
            response,
        } => {
            // Get the response channel from the response map
            if let Some(response_tx) = connection.response_map.lock().unwrap().remove(&request_id) {
                // Send the response
                response_tx.send(response).unwrap();
            } else {
                panic!("Received response for unknown request ID: {}", request_id);
            }
        }
    };
}

#[derive(Debug)]
pub enum ConnectError {}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn connect() -> Result<Arc<ClientConnection>, ConnectError> {
    let cookies = get_cookies().await;
    // Use the refresh token cookie to get a new access token
    let reqwest = reqwest::Client::builder()
        .cookie_provider(cookies.clone())
        .build()
        .unwrap();
    // Issue POST to /auth/refresh
    let response = reqwest
        .post(get_api_domain().join("/auth/refresh").unwrap())
        .send()
        .await
        .unwrap();

    let ws_stream = establish_websocket_connection(&cookies).await;
    let (write, mut read) = ws_stream.split();
    let (stop_signal_tx, mut stop_signal_rx) = oneshot::channel::<()>();

    let (connection_tx, connection_rx) = oneshot::channel::<Arc<ClientConnection>>();

    let process_messages: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        let connection = connection_rx.await.unwrap();

        loop {
            select! {
                _ = &mut stop_signal_rx => {
                    break;
                }
                message = read.next() => {
                    match message {
                        Some(Ok(Message::Text(message))) => {
                            handle_client_message(&*connection, &message);
                        }
                        Some(Ok(message)) => {
                            println!("Received message: {:?}", message);
                        }
                        Some(Err(err)) => {
                            println!("Error reading message: {:?}", err);
                        }
                        None => {
                            break;
                        }
                    }
                }
            }
        }
    });

    let connection = Arc::new(ClientConnection {
        write: write.into(),
        stop_signal_tx: Some(stop_signal_tx).into(),
        process_messages: Some(process_messages).into(),
        response_map: HashMap::new().into(),
    });

    connection_tx.send(Arc::clone(&connection)).unwrap();

    Ok(connection)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub async fn login() {
    let cookies = get_cookies().await;
    let ws_stream = establish_websocket_connection(&cookies).await;
    let (mut write, mut read) = ws_stream.split();

    write
        .send(Message::Text(
            serde_json::to_string(&WebsocketClientMessage::LoginRequest {}).unwrap(),
        ))
        .await
        .unwrap();

    loop {
        match read.next().await {
            Some(Ok(Message::Text(message))) => {
                match serde_json::from_str::<WebsocketServerMessage>(&message) {
                    Ok(WebsocketServerMessage::LoginUrl { url }) => {
                        println!("Please login with this URL:\n{}", url);
                    }
                    Ok(WebsocketServerMessage::AuthCodeUrl { url }) => {
                        let config_dir = dirs::config_dir().unwrap();

                        match tokio::fs::DirBuilder::new()
                            .recursive(true)
                            .create(&config_dir)
                            .await
                        {
                            Ok(_) => {}
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::AlreadyExists {
                                    // The directory already exists, so we can continue
                                } else {
                                    panic!("Failed to create directory: {:?}", e);
                                }
                            }
                        };

                        let unet_config_dir = config_dir.join("unet");

                        match tokio::fs::DirBuilder::new()
                            .mode(0o700)
                            .create(&unet_config_dir)
                            .await
                        {
                            Ok(_) => {}
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::AlreadyExists {
                                    // The directory already exists, so we can continue
                                } else {
                                    panic!("Failed to create directory: {:?}", e);
                                }
                            }
                        }

                        let cookie_path = unet_config_dir.join("cookies.json");

                        // Use the auth code to get the credentials as cookies
                        let cookie_store =
                            std::sync::Arc::new(CookieStoreMutex::new(CookieStore::new(None)));
                        let reqwest = reqwest::Client::builder()
                            .cookie_provider(cookie_store.clone())
                            .build()
                            .unwrap();

                        reqwest.get(url).send().await.unwrap();

                        let mut writer = std::fs::File::create(cookie_path)
                            .map(std::io::BufWriter::new)
                            .unwrap();

                        let save_cookie_result = reqwest_cookie_store::CookieStore::save_json(
                            cookie_store.lock().unwrap().deref_mut(),
                            &mut writer,
                        );

                        if let Err(e) = save_cookie_result {
                            println!("Failed to save cookies: {:?}", e);
                        }

                        break;
                    }
                    Ok(_) => {
                        println!("Received message: {:?}", message);
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                    }
                };
            }
            Some(Ok(message)) => {
                println!("Received message: {:?}", message);
            }
            Some(Err(err)) => {
                println!("Error reading message: {:?}", err);
            }
            None => {
                break;
            }
        }
    }
}

pub async fn logout() {
    println!("Logout of unet");
}

#[derive(Debug)]
pub enum ServeError {
    ConnectError(ConnectError),
}

impl From<ConnectError> for ServeError {
    fn from(error: ConnectError) -> Self {
        ServeError::ConnectError(error)
    }
}

pub async fn serve() -> Result<(), ServeError> {
    log!("Connecting to unet...");
    let client = connect().await?;

    log!("Getting auth state...");

    let user = if let Ok(user) = get_user(&client).await {
        user
    } else {
        log!("Not logged in!");

        return Ok(());
    };

    log!("logged in as {}", user.email);

    log!("Serving this host...");
    futures::future::pending::<()>().await;

    log!("Exiting...");

    Ok(())
}

pub struct ExistingCredentials {}

enum GetExistingCredentialsError {
    NoCredentials,
}

async fn get_existing_credentials(
    full_hostname: &str,
) -> Result<ExistingCredentials, GetExistingCredentialsError> {
    // Ok(ExistingCredentials {})
    Err(GetExistingCredentialsError::NoCredentials)
}

pub enum HostRegistationAuthorizationError {}

async fn host_registation_authorization(
    full_hostname: &str,
) -> Result<ExistingCredentials, HostRegistationAuthorizationError> {
    println!("connecting to unet.tech...");
    let client = connect().await;
    println!("sending host registration authorization request to peter...");
    println!("visit https://unet.tech to authorize the request");
    println!("waiting for host registration authorization...");

    println!("host registration authorized");
    Ok(ExistingCredentials {})
}

async fn write_credentials(credentials: &ExistingCredentials) {
    println!("writing credentials to ./.unet");
}

pub enum RefreshCredentialsError {
    RefreshTokenExpired,
}

async fn refresh_credentials(
    credentials: ExistingCredentials,
) -> Result<ExistingCredentials, RefreshCredentialsError> {
    println!("refreshing credentials...");
    Ok(credentials)
}

pub enum RegisterError {
    RefreshCredentialsError(RefreshCredentialsError),
    HostRegistrationAuthorizationError(HostRegistationAuthorizationError),
}

impl From<RefreshCredentialsError> for RegisterError {
    fn from(error: RefreshCredentialsError) -> Self {
        RegisterError::RefreshCredentialsError(error)
    }
}

impl From<HostRegistationAuthorizationError> for RegisterError {
    fn from(error: HostRegistationAuthorizationError) -> Self {
        RegisterError::HostRegistrationAuthorizationError(error)
    }
}

pub async fn register(
    full_hostname: &str,
    accept_alternative: &bool,
    output: Option<&str>,
    input: Option<&str>,
) -> Result<ExistingCredentials, RegisterError> {
    dbg!(full_hostname);

    let credentials = host_registation_authorization(full_hostname).await?;

    write_credentials(&credentials).await;

    Ok(credentials)

    // println!("looking for existing credentials...");
    // let credentials = match get_existing_credentials(full_hostname).await {
    //     Ok(credentials) => {
    //         println!("found existing credentials");
    //         let credentials = match refresh_credentials(credentials).await {
    //             Ok(credentials) => credentials,
    //             Err(RefreshCredentialsError::RefreshTokenExpired {}) => {
    //                 println!("refresh token expired");
    //                 let credentials = host_registation_authorization(full_hostname).await?;
    //                 credentials
    //             }
    //         };
    //         credentials
    //     }
    //     Err(GetExistingCredentialsError::NoCredentials) => {
    //         println!("no existing credentials found");
    //         let credentials = host_registation_authorization(full_hostname).await?;
    //         credentials
    //     }
    // };

    // write_credentials(&credentials).await;

    // Ok(())
}
