use {
    serde::{Deserialize, Serialize},
    url::Url,
};

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use {
    futures_util::{stream::SplitSink, SinkExt, StreamExt},
    http::Request,
    std::mem::replace,
    tokio::{fs::read_to_string, net::TcpStream, select, sync::oneshot},
    tokio_tungstenite::{
        connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
    },
};

#[cfg(feature = "aws")]
use {
    aws_lambda_events::event::apigw::{
        ApiGatewayProxyResponse, ApiGatewayV2httpRequest, ApiGatewayV2httpResponse,
        ApiGatewayWebsocketProxyRequest,
    },
    aws_sdk_apigatewaymanagement as apigatewaymanagement,
    aws_sdk_apigatewaymanagement::primitives::Blob,
    aws_sdk_cloudformation as cloudformation,
    aws_sdk_cloudformation::types::Stack,
    aws_sdk_cognitoidentityprovider as cognitoidentityprovider,
    aws_sdk_cognitoidentityprovider::types::{
        TimeUnitsType, TokenValidityUnitsType, UserPoolClientType,
    },
    aws_sdk_dynamodb as dynamodb,
    aws_sdk_dynamodb::{operation::get_item::GetItemOutput, types::AttributeValue},
    aws_sdk_s3 as s3,
    aws_sdk_s3::presigning::{PresignedRequest, PresigningConfig},
    http::{header::LOCATION, HeaderMap, Method, Uri},
    jsonwebtoken as jwt,
    jsonwebtoken::{
        jwk::{AlgorithmParameters, JwkSet, RSAKeyParameters},
        Algorithm::RS256,
        DecodingKey, Validation,
    },
    lambda_runtime::{Error, LambdaEvent},
    serde_json::{json, Value},
    std::collections::HashMap,
};

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
enum WebsocketClientMessage {
    LoginRequest {},
    GeneratePresignedUrl { object_path: String },
}

#[derive(Serialize, Deserialize)]
struct Credentials {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "tag", content = "content")]
enum WebsocketServerMessage {
    LoginUrl { url: String },
    LoginCredentials { credentials: Credentials },
    PresignedUrl { url: String },
}

#[cfg(feature = "aws")]
pub async fn lambda_main() {
    let aws = get_aws().await;
    let service_fn = lambda_runtime::service_fn(|event| handle_lambda_event(&aws, event));
    lambda_runtime::run(service_fn).await.unwrap();
}

#[cfg(feature = "aws")]
#[derive(Deserialize)]
struct Tokens {
    id_token: String,
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: String,
}

#[cfg(feature = "aws")]
async fn get_tokens_from_authorization_code(aws: &AWS, code: &str) -> Tokens {
    let client_secret = aws.user_pool_client.client_secret.clone().unwrap();
    let token_url = get_auth_domain().join("/oauth2/token").unwrap();
    let callback_url = get_api_domain().join("/auth/callback").unwrap();

    let form = {
        let mut payload = HashMap::new();
        payload.insert("grant_type", "authorization_code".to_string());
        payload.insert("client_id", aws.user_pool_client_id.to_string());
        payload.insert("client_secret", client_secret);
        payload.insert("redirect_uri", callback_url.to_string());
        payload.insert("code", code.to_string());
        payload
    };

    // Make the POST request to exchange the authorization code for tokens
    let response = aws
        .reqwest
        .post(token_url.as_str())
        .form(&form)
        .send()
        .await
        .unwrap();
    let json = response.json::<Value>().await.unwrap();

    // Deserialize the json response into a TokenResponse
    let tokens = serde_json::from_value::<Tokens>(json).unwrap();

    assert_eq!(tokens.token_type, "Bearer");

    tokens
}

#[cfg(feature = "aws")]
fn get_refresh_token_expires_in(aws: &AWS) -> i64 {
    let validity_in_seconds: i64 = match aws
        .user_pool_client
        .token_validity_units
        .as_ref()
        .unwrap_or(&TokenValidityUnitsType::builder().build())
        .refresh_token
        .as_ref()
        .unwrap_or(&TimeUnitsType::Days)
    {
        TimeUnitsType::Seconds => 1,
        TimeUnitsType::Minutes => 60,
        TimeUnitsType::Hours => 60 * 60,
        TimeUnitsType::Days => 60 * 60 * 24,
        _ => panic!("Unknown refresh token validity units"),
    };

    validity_in_seconds * aws.user_pool_client.refresh_token_validity as i64
}

#[cfg(feature = "aws")]
fn auth_http_response(
    access_token: &str,
    access_token_expires_in: i64,
    refresh_token: &str,
    refresh_token_expires_in: i64,
) -> ApiGatewayV2httpResponse {
    let headers = {
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, get_root_domain().as_str().parse().unwrap());
        headers
    };

    let api_domain = get_api_domain();

    let cookie_domain = api_domain.host_str().unwrap();
    let cookies = [
        format!(
            "accessToken={}; Domain={}; HttpOnly; Max-Age={}; Path=/; SameSite=Lax; Secure",
            access_token, cookie_domain, access_token_expires_in
        ),
        format!(
            "refreshToken={}; Domain={}; HttpOnly; Max-Age={}; Path=/auth; SameSite=Lax; Secure",
            refresh_token, cookie_domain, refresh_token_expires_in,
        ),
    ]
    .to_vec();

    ApiGatewayV2httpResponse {
        status_code: 302,
        headers,

        cookies,
        ..Default::default()
    }
}

#[cfg(feature = "aws")]
async fn auth_callback(
    aws: &AWS,
    http_request: &ApiGatewayV2httpRequest,
) -> ApiGatewayV2httpResponse {
    let query_string_parameters = &http_request.query_string_parameters;
    let code = query_string_parameters.first("code").unwrap();
    let tokens = get_tokens_from_authorization_code(aws, code).await;
    let state = query_string_parameters.first("state").unwrap_or("{}");
    let state: AuthState = serde_json::from_str(state).unwrap();
    dbg!(&state);

    if let Some(connection_id) = state.connection_id {
        post_to_connection(
            aws,
            &connection_id,
            &WebsocketServerMessage::LoginCredentials {
                credentials: Credentials {
                    id_token: tokens.id_token.clone(),
                    access_token: tokens.access_token.clone(),
                    refresh_token: tokens.refresh_token.clone(),
                },
            },
        )
        .await;
    }
    auth_http_response(
        &tokens.access_token,
        tokens.expires_in,
        &tokens.refresh_token,
        get_refresh_token_expires_in(aws),
    )
}

#[cfg(feature = "aws")]
async fn auth_logout(_http_request: &ApiGatewayV2httpRequest) -> ApiGatewayV2httpResponse {
    auth_http_response("", 0, "", 0)
}

#[cfg(feature = "aws")]
async fn auth_refresh(_http_request: &ApiGatewayV2httpRequest) -> ApiGatewayV2httpResponse {
    ApiGatewayV2httpResponse {
        status_code: 200,
        ..Default::default()
    }
}

#[cfg(feature = "aws")]
fn method_not_allowed() -> ApiGatewayV2httpResponse {
    ApiGatewayV2httpResponse {
        status_code: 405,
        ..Default::default()
    }
}

#[cfg(feature = "aws")]
fn not_found() -> ApiGatewayV2httpResponse {
    ApiGatewayV2httpResponse {
        status_code: 404,
        ..Default::default()
    }
}

#[cfg(feature = "aws")]
async fn handle_http_request(
    aws: &AWS,
    http_request: &ApiGatewayV2httpRequest,
) -> ApiGatewayV2httpResponse {
    let request_context = &http_request.request_context;
    let http = &request_context.http;
    let path = http.path.as_ref().unwrap();
    let method = &http.method;

    match path.as_str() {
        "/auth/callback" => match *method {
            Method::GET => auth_callback(aws, http_request).await,
            _ => method_not_allowed(),
        },
        "/auth/logout" => match *method {
            Method::POST => auth_logout(http_request).await,
            _ => method_not_allowed(),
        },
        "/auth/refresh" => match *method {
            Method::POST => auth_refresh(http_request).await,
            _ => method_not_allowed(),
        },
        _ => not_found(),
    }
}

#[cfg(feature = "aws")]
fn get_stack_output(stack: &Stack, output_key: &str) -> String {
    stack
        .outputs
        .as_ref()
        .unwrap()
        .iter()
        .find(|output| output.output_key.as_ref().unwrap() == output_key)
        .unwrap()
        .output_value
        .as_ref()
        .unwrap()
        .clone()
}

#[cfg(feature = "aws")]
pub async fn get_aws() -> AWS {
    let config = aws_config::load_from_env().await;
    let cloudformation = cloudformation::Client::new(&config);
    let stack = cloudformation
        .describe_stacks()
        .stack_name(get_stack_name().as_str())
        .send()
        .await
        .unwrap()
        .stacks
        .unwrap()
        .pop()
        .unwrap();
    let dynamodb = dynamodb::Client::new(&config);

    let s3_bucket = get_stack_output(&stack, "S3Bucket");
    let user_pool_id = get_stack_output(&stack, "UserPoolId");
    let user_pool_client_id = get_stack_output(&stack, "UserPoolClientId");
    let websocket_endpoint_url =
        Url::parse(get_stack_output(&stack, "WebsocketEndpointUrl").as_str()).unwrap();
    let function_cloudwatch_log_group = get_stack_output(&stack, "FunctionCloudwatchLogGroup");
    let connections_table_name = get_stack_output(&stack, "ConnectionsTableName");

    let cognitoidentityprovider = cognitoidentityprovider::Client::new(&config);
    let user_pool_client = cognitoidentityprovider
        .describe_user_pool_client()
        .set_user_pool_id(Some(user_pool_id.to_string()))
        .set_client_id(Some(user_pool_client_id.to_string()))
        .send()
        .await
        .unwrap()
        .user_pool_client
        .unwrap();

    let api_gateway_management = apigatewaymanagement::Client::from_conf(
        apigatewaymanagement::config::Builder::from(&config)
            .endpoint_url(websocket_endpoint_url.clone())
            .build(),
    );

    let reqwest = reqwest::Client::new();

    let jwks: HashMap<String, DecodingKey> = reqwest
        .get(get_stack_output(&stack, "JwksUrl").as_str())
        .send()
        .await
        .unwrap()
        .json::<JwkSet>()
        .await
        .unwrap()
        .keys
        .iter()
        .map(|jwk| {
            let rsa: &RSAKeyParameters = match &jwk.algorithm {
                AlgorithmParameters::RSA(rsa) => rsa,
                _ => panic!("JWK is not an RSA key"),
            };
            let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();
            (jwk.common.key_id.clone().unwrap(), decoding_key)
        })
        .collect();

    let s3 = s3::Client::new(&config);

    AWS {
        reqwest,
        dynamodb,
        s3,
        user_pool_client,
        jwks,
        api_gateway_management,
        s3_bucket,
        user_pool_client_id,
        function_cloudwatch_log_group,
        connections_table_name,
    }
}

#[cfg(feature = "aws")]
pub struct AWS {
    reqwest: reqwest::Client,
    dynamodb: dynamodb::Client,
    s3: s3::Client,
    user_pool_client: UserPoolClientType,
    jwks: HashMap<String, DecodingKey>,
    api_gateway_management: apigatewaymanagement::Client,
    pub s3_bucket: String,
    user_pool_client_id: String,
    #[allow(dead_code)] // TODO
    function_cloudwatch_log_group: String,
    connections_table_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthState {
    connection_id: Option<String>,
}

#[cfg(feature = "aws")]
async fn login_request(aws: &AWS, connection_id: &str) {
    let mut login_url = get_auth_domain().join("/oauth2/authorize").unwrap();
    login_url
        .query_pairs_mut()
        .append_pair("client_id", aws.user_pool_client_id.as_str())
        .append_pair("response_type", "code")
        .append_pair("scope", "email openid")
        .append_pair(
            "redirect_uri",
            get_api_domain().join("/auth/callback").unwrap().as_str(),
        )
        .append_pair(
            "state",
            serde_json::to_string(&AuthState {
                connection_id: Some(connection_id.to_string()),
            })
            .unwrap()
            .as_str(),
        );
    post_to_connection(
        aws,
        connection_id,
        &WebsocketServerMessage::LoginUrl {
            url: login_url.to_string(),
        },
    )
    .await;
}

#[cfg(feature = "aws")]
async fn post_to_connection(aws: &AWS, connection_id: &str, data: &WebsocketServerMessage) {
    aws.api_gateway_management
        .post_to_connection()
        .connection_id(connection_id)
        .data(Blob::new(serde_json::to_string(data).unwrap()))
        .send()
        .await
        .unwrap();
}

#[cfg(feature = "aws")]
async fn handle_websocket_message(aws: &AWS, connection_id: &str, body: &str) {
    match (
        serde_json::from_str::<WebsocketClientMessage>(body),
        get_connection(aws, connection_id).await,
    ) {
        (Ok(WebsocketClientMessage::LoginRequest {}), _) => {
            login_request(aws, connection_id).await;
        }
        (
            Ok(WebsocketClientMessage::GeneratePresignedUrl { object_path }),
            Connection::Authorized { .. },
        ) => {
            let presigned_url = generate_presigned_url(aws, &object_path).await;
            post_to_connection(
                aws,
                connection_id,
                &WebsocketServerMessage::PresignedUrl {
                    url: presigned_url.url.to_string(),
                },
            )
            .await;
        }
        (Err(err), _) => {
            println!("Error deserializing websocket message: {:?}", err);
        }
        (Ok(message), Connection::Unauthorized) => {
            println!("Unauthorized websocket message: {:?}", message);
        }
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct AccessTokenClaims {
    auth_time: i64,
    client_id: String,
    event_id: String,
    exp: i64,
    iat: i64,
    iss: String,
    jti: String,
    origin_jti: String,
    scope: String,
    sub: String,
    token_use: String,
    username: String,
    version: i64,
}

#[cfg(feature = "aws")]
enum AccessTokenClaimsError {
    NoAuthorizationHeader,
    InvalidAuthorizationHeader,
    InvalidKid,
    JwtDecodeError,
}

#[cfg(feature = "aws")]
fn get_access_token_claims(
    aws: &AWS,
    headers: &HeaderMap,
) -> Result<AccessTokenClaims, AccessTokenClaimsError> {
    // Get the `sub` claim from the JWT token passed in the `Authorization` header
    let mut authorization_header_parts = headers
        .get("authorization")
        .ok_or(AccessTokenClaimsError::NoAuthorizationHeader)?
        .to_str()
        .map_err(|_| AccessTokenClaimsError::InvalidAuthorizationHeader)?
        .split_whitespace();
    let authorization_header_parts = (
        authorization_header_parts.next(), // Scheme
        authorization_header_parts.next(), // Parameter
        authorization_header_parts.next(), // None
    );

    let jwt_token = match authorization_header_parts {
        (Some("Bearer"), Some(jwt_token), None) => jwt_token,
        _ => return Err(AccessTokenClaimsError::InvalidAuthorizationHeader),
    };

    let kid = jwt::decode_header(jwt_token)
        .map_err(|_| AccessTokenClaimsError::JwtDecodeError)?
        .kid
        .ok_or(AccessTokenClaimsError::InvalidKid)?;

    let decoding_key = aws
        .jwks
        .get(&kid)
        .ok_or(AccessTokenClaimsError::InvalidKid)?;

    Ok(
        jwt::decode::<AccessTokenClaims>(jwt_token, decoding_key, &Validation::new(RS256))
            .map_err(|_| AccessTokenClaimsError::JwtDecodeError)?
            .claims,
    )
}

#[cfg(feature = "aws")]
enum Connection {
    Authorized { user_id: String },
    Unauthorized,
}

#[cfg(feature = "aws")]
async fn create_connection(aws: &AWS, connection_id: &str, connection: &Connection) {
    match connection {
        Connection::Authorized { user_id } => {
            aws.dynamodb
                .put_item()
                .table_name(aws.connections_table_name.as_str())
                .item(
                    "connection_id",
                    AttributeValue::S(connection_id.to_string()),
                )
                .item("user_id", AttributeValue::S(user_id.to_string()))
                .send()
                .await
                .unwrap();
        }
        Connection::Unauthorized => {}
    }
}

#[cfg(feature = "aws")]
async fn delete_connection(aws: &AWS, connection_id: &str) -> bool {
    aws.dynamodb
        .delete_item()
        .table_name(aws.connections_table_name.as_str())
        .key(
            "connection_id",
            dynamodb::types::AttributeValue::S(connection_id.to_string()),
        )
        .send()
        .await
        .is_ok()
}

#[cfg(feature = "aws")]
async fn get_connection(aws: &AWS, connection_id: &str) -> Connection {
    let mut item: HashMap<String, AttributeValue> = aws
        .dynamodb
        .get_item()
        .table_name(aws.connections_table_name.as_str())
        .key(
            "connection_id",
            AttributeValue::S(connection_id.to_string()),
        )
        .send()
        .await
        .unwrap_or_else(|_| GetItemOutput::builder().build())
        .item
        .unwrap_or_default();

    match item.remove("user_id") {
        Some(AttributeValue::S(user_id)) => Connection::Authorized { user_id },
        _ => Connection::Unauthorized,
    }
}

#[cfg(feature = "aws")]
async fn handle_websocket_connect(aws: &AWS, connection_id: &str, headers: &HeaderMap) {
    if let Ok(access_token_claims) = get_access_token_claims(aws, headers) {
        dbg!(&access_token_claims);
        create_connection(
            aws,
            connection_id,
            &Connection::Authorized {
                user_id: access_token_claims.sub,
            },
        )
        .await;
    }
}

#[cfg(feature = "aws")]
async fn handle_websocket_disconnect(aws: &AWS, connection_id: &str) {
    delete_connection(aws, connection_id).await;
}

#[cfg(feature = "aws")]
async fn handle_lambda_event(aws: &AWS, event: LambdaEvent<Value>) -> Result<Value, Error> {
    let (event, _context) = event.into_parts();

    if let Ok(websocket_request) =
        ApiGatewayWebsocketProxyRequest::<Value, Value>::deserialize(&event)
    {
        // websocket
        dbg!(&websocket_request);
        let request_context = &websocket_request.request_context;
        let route_key = request_context.route_key.as_ref().unwrap();
        let connection_id = request_context.connection_id.as_ref().unwrap();
        match route_key.as_str() {
            "$connect" => {
                handle_websocket_connect(aws, connection_id, &websocket_request.headers).await;
            }
            "$disconnect" => {
                handle_websocket_disconnect(aws, connection_id).await;
            }
            _ => {
                handle_websocket_message(
                    aws,
                    connection_id,
                    websocket_request.body.as_ref().unwrap(),
                )
                .await;
            }
        };
        Ok(json!(ApiGatewayProxyResponse {
            status_code: 200,
            ..Default::default()
        }))
    } else if let Ok(http_request) = ApiGatewayV2httpRequest::deserialize(&event) {
        // http
        dbg!(&http_request);
        let http_response = handle_http_request(aws, &http_request).await;
        dbg!(&http_response);
        Ok(json!(http_response))
    } else {
        let unmatched_event = event;
        panic!("unmatched_event = {:?}", unmatched_event);
    }
}

#[cfg(feature = "aws")]
struct PresignedUrl {
    url: Uri,
    #[allow(dead_code)]
    headers: HeaderMap,
}

#[cfg(feature = "aws")]
async fn generate_presigned_url(aws: &AWS, object_path: &String) -> PresignedUrl {
    let presigned_url: PresignedRequest = aws
        .s3
        .get_object()
        .bucket(&aws.s3_bucket)
        .key(object_path)
        .presigned(PresigningConfig::expires_in(std::time::Duration::from_secs(30 * 60)).unwrap())
        .await
        .unwrap();
    return PresignedUrl {
        url: presigned_url.uri().clone(),
        headers: presigned_url.headers().clone(),
    };
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
enum GetCredentialsError {
    NoCredentials,
    InvalidCredentials,
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn get_credentials() -> Result<Credentials, GetCredentialsError> {
    let mut credentials_path = dirs::config_dir().ok_or(GetCredentialsError::NoCredentials)?;
    credentials_path.push("unet");
    credentials_path.push("credentials.json");

    let credentials_str = read_to_string(credentials_path)
        .await
        .map_err(|_| GetCredentialsError::NoCredentials)?;

    serde_json::from_str::<Credentials>(&credentials_str)
        .map_err(|_| GetCredentialsError::InvalidCredentials)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn make_connection() -> WebSocketStream<MaybeTlsStream<TcpStream>> {
    let websocket_domain = get_websocket_domain();

    let request_builder = Request::builder()
        .uri(websocket_domain.as_str())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("Sec-WebSocket-Version", "13")
        .header("Host", websocket_domain.host_str().unwrap());

    let request_builder = match get_credentials().await {
        Ok(credentials) => request_builder.header(
            "Authorization",
            format!("Bearer {}", credentials.access_token),
        ),
        Err(_) => request_builder,
    };

    let request = request_builder.body(()).unwrap();

    let (ws_stream, _) = connect_async(request).await.unwrap();

    ws_stream
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
enum ClientConnection {
    Open {
        write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        close_tx: oneshot::Sender<()>,
    },
    Closed,
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn close_client_connection(connection: &mut ClientConnection) {
    if let ClientConnection::Open {
        mut write,
        close_tx,
    } = replace(connection, ClientConnection::Closed)
    {
        write.close().await.unwrap();
        close_tx.send(()).unwrap();
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn write_to_client_connection(
    connection: &mut ClientConnection,
    message: &WebsocketClientMessage,
) {
    match connection {
        ClientConnection::Open { write, .. } => {
            write
                .send(Message::Text(serde_json::to_string(message).unwrap()))
                .await
                .unwrap();
        }
        ClientConnection::Closed => {}
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
async fn handle_client_message(connection: &mut ClientConnection, message: &str) {
    // Decode the message as a WebsocketServerMessage
    let message: WebsocketServerMessage = serde_json::from_str(message).unwrap();
    match message {
        WebsocketServerMessage::LoginUrl { url } => {
            println!("Please login with this URL:\n{}", url);
        }
        WebsocketServerMessage::LoginCredentials { credentials } => {
            // Store the credentials
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

            let credentials_path = unet_config_dir.join("credentials.json");
            let credentials = serde_json::to_string_pretty(&credentials).unwrap();
            tokio::fs::write(credentials_path, credentials)
                .await
                .unwrap();

            close_client_connection(connection).await;
        }
        WebsocketServerMessage::PresignedUrl { url } => {
            println!("Presigned URL: {}", url);
        }
    };
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub async fn login() {
    let ws_stream = make_connection().await;
    let (write, mut read) = ws_stream.split();
    let (close_tx, mut close_rx) = oneshot::channel::<()>();
    let mut connection = ClientConnection::Open { write, close_tx };

    write_to_client_connection(&mut connection, &WebsocketClientMessage::LoginRequest {}).await;

    loop {
        select! {
            _ = &mut close_rx => {
                break;
            }
            message = read.next() => {
                match message {
                    Some(Ok(Message::Text(message))) => {
                        handle_client_message(&mut connection, &message).await;
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
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub async fn logout() {
    println!("Logout of unet");
}
