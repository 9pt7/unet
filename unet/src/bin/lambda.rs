use unet::cloud::{
    get_api_domain, get_auth_domain, get_root_domain, get_stack_name, User, WebsocketClientMessage,
    WebsocketClientRequest, WebsocketServerError, WebsocketServerMessage, WebsocketServerResponse,
};

use {
    serde::{Deserialize, Serialize},
    url::Url,
};

use {
    aws_lambda_events::{
        encodings::Body,
        event::apigw::{
            ApiGatewayProxyResponse, ApiGatewayV2httpRequest, ApiGatewayV2httpResponse,
            ApiGatewayWebsocketProxyRequest,
        },
    },
    aws_sdk_apigatewaymanagement as apigatewaymanagement,
    aws_sdk_apigatewaymanagement::primitives::Blob,
    aws_sdk_cloudformation as cloudformation,
    aws_sdk_cloudformation::types::Stack,
    aws_sdk_cognitoidentityprovider as cognitoidentityprovider,
    aws_sdk_cognitoidentityprovider::{
        operation::initiate_auth::InitiateAuthOutput,
        types::{
            AuthFlowType, AuthenticationResultType, TimeUnitsType, TokenValidityUnitsType,
            UserPoolClientType,
        },
    },
    aws_sdk_dynamodb as dynamodb,
    aws_sdk_dynamodb::{operation::get_item::GetItemOutput, types::AttributeValue},
    aws_sdk_s3 as s3,
    aws_sdk_s3::presigning::{PresignedRequest, PresigningConfig},
    base64::Engine,
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

async fn lambda_main() {
    let aws = get_aws().await;
    let service_fn = lambda_runtime::service_fn(|event| handle_lambda_event(&aws, event));
    lambda_runtime::run(service_fn).await.unwrap();
}

#[derive(Deserialize)]
struct Tokens {
    id_token: String,
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: String,
}

fn get_token_endpoint_url() -> Url {
    get_auth_domain().join("/oauth2/token").unwrap()
}

async fn get_tokens_from_authorization_code(aws: &AWS, code: &str) -> Tokens {
    let form = {
        let mut payload = HashMap::new();
        payload.insert("grant_type", "authorization_code".to_string());
        payload.insert("client_id", aws.user_pool_client_id.to_string());
        payload.insert(
            "client_secret",
            aws.user_pool_client
                .client_secret
                .as_ref()
                .unwrap()
                .to_string(),
        );
        payload.insert(
            "redirect_uri",
            get_api_domain().join("/auth/callback").unwrap().to_string(),
        );
        payload.insert("code", code.to_string());
        payload
    };

    // Make the POST request to exchange the authorization code for tokens
    let response = aws
        .reqwest
        .post(get_token_endpoint_url().as_str())
        .form(&form)
        .send()
        .await
        .unwrap();
    let tokens = response.json::<Tokens>().await.unwrap();

    assert_eq!(tokens.token_type, "Bearer");

    tokens
}

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

fn access_token_cookie(access_token: &str, expires_in: i64) -> String {
    format!(
        "accessToken={}; Domain={}; HttpOnly; Max-Age={}; Path=/; SameSite=Lax; Secure",
        access_token,
        get_api_domain().host_str().unwrap(),
        expires_in
    )
}

fn refresh_token_cookie(aws: &AWS, refresh_token: &str, expires_in: i64) -> String {
    format!(
        "refreshToken={}; Domain={}; HttpOnly; Max-Age={}; Path=/auth; SameSite=Lax; Secure",
        refresh_token,
        get_api_domain().host_str().unwrap(),
        expires_in,
    )
}

fn redirect_to_root_domain_header_map() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, get_root_domain().as_str().parse().unwrap());
    headers
}

fn auth_http_response(
    aws: &AWS,
    access_token: &str,
    access_token_expires_in: i64,
    refresh_token: &str,
    refresh_token_expires_in: i64,
) -> ApiGatewayV2httpResponse {
    let headers = redirect_to_root_domain_header_map();

    let api_domain = get_api_domain();

    let cookies = [
        access_token_cookie(access_token, access_token_expires_in),
        refresh_token_cookie(aws, refresh_token, refresh_token_expires_in),
    ]
    .to_vec();

    ApiGatewayV2httpResponse {
        status_code: 302,
        headers,
        cookies,
        ..Default::default()
    }
}

async fn update_user_from_id_token(aws: &AWS, id_token: &IdTokenClaims) {
    aws.dynamodb
        .put_item()
        .table_name(aws.users_table_name.as_str())
        .item("user_id", AttributeValue::S(id_token.sub.to_string()))
        .item("email", AttributeValue::S(id_token.email.to_string()))
        .send()
        .await
        .unwrap();
}

async fn auth_callback(
    aws: &AWS,
    http_request: &ApiGatewayV2httpRequest,
) -> ApiGatewayV2httpResponse {
    let query_string_parameters = &http_request.query_string_parameters;
    let state = query_string_parameters.first("state").unwrap_or("{}");
    let state: AuthState = serde_json::from_str(state).unwrap();
    dbg!(&state);
    let code = query_string_parameters.first("code").unwrap();

    if let Some(connection_id) = state.connection_id {
        post_to_connection(
            aws,
            &connection_id,
            &WebsocketServerMessage::AuthCodeUrl {
                url: {
                    let mut url = get_api_domain().join("/auth/callback").unwrap();
                    url.query_pairs_mut().append_pair("code", code);
                    url.to_string()
                },
            },
        )
        .await;

        let headers = redirect_to_root_domain_header_map();

        ApiGatewayV2httpResponse {
            status_code: 302,
            headers,
            ..Default::default()
        }
    } else {
        let tokens = get_tokens_from_authorization_code(aws, code).await;

        let id_token = get_id_token_claims(aws, &tokens.id_token).unwrap();
        dbg!(&id_token);
        update_user_from_id_token(aws, &id_token).await;

        auth_http_response(
            aws,
            &tokens.access_token,
            tokens.expires_in,
            &tokens.refresh_token,
            get_refresh_token_expires_in(aws),
        )
    }
}

async fn auth_logout(
    aws: &AWS,
    _http_request: &ApiGatewayV2httpRequest,
) -> ApiGatewayV2httpResponse {
    auth_http_response(aws, "", 0, "", 0)
}

fn get_refresh_token_from_http_request(
    aws: &AWS,
    http_request: &ApiGatewayV2httpRequest,
) -> Option<String> {
    let cookies = if let Some(cookies) = http_request.cookies.as_ref() {
        cookies
    } else {
        return None;
    };

    for cookie in cookies {
        let cookie = if let Ok(cookie) = cookie::Cookie::parse(cookie) {
            cookie
        } else {
            continue;
        };

        if cookie.name() == "refreshToken" {
            return Some(cookie.value().to_string());
        }
    }

    None
}

#[derive(Deserialize)]
struct RefreshedTokens {
    access_token: String,
    expires_in: i64,
    id_token: String,
    token_type: String,
}

async fn auth_refresh(
    aws: &AWS,
    http_request: &ApiGatewayV2httpRequest,
) -> ApiGatewayV2httpResponse {
    let refresh_token =
        if let Some(refresh_token) = get_refresh_token_from_http_request(aws, http_request) {
            refresh_token
        } else {
            return bad_request();
        };

    // Decode the refresh token to get the username

    // Make the POST request to exchange the refresh token for tokens
    let form = {
        let mut payload = HashMap::new();
        payload.insert("grant_type", "refresh_token".to_string());
        payload.insert("client_id", aws.user_pool_client_id.to_string());
        payload.insert(
            "client_secret",
            aws.user_pool_client
                .client_secret
                .as_ref()
                .unwrap()
                .to_string(),
        );
        payload.insert("refresh_token", refresh_token);
        payload
    };

    // Make the POST request to exchange the authorization code for tokens
    let response = aws
        .reqwest
        .post(get_token_endpoint_url().as_str())
        .form(&form)
        .send()
        .await
        .unwrap();
    let tokens = response.json::<RefreshedTokens>().await.unwrap();

    let id_token = get_id_token_claims(aws, &tokens.id_token).unwrap();
    update_user_from_id_token(aws, &id_token).await;

    let cookies = [access_token_cookie(&tokens.access_token, tokens.expires_in)].to_vec();

    ApiGatewayV2httpResponse {
        status_code: 200,
        cookies,
        body: Some(Body::Text(json!({}).to_string())),
        ..Default::default()
    }
}

fn bad_request() -> ApiGatewayV2httpResponse {
    ApiGatewayV2httpResponse {
        status_code: 400,
        ..Default::default()
    }
}

fn not_found() -> ApiGatewayV2httpResponse {
    ApiGatewayV2httpResponse {
        status_code: 404,
        ..Default::default()
    }
}

fn method_not_allowed() -> ApiGatewayV2httpResponse {
    ApiGatewayV2httpResponse {
        status_code: 405,
        ..Default::default()
    }
}

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
            Method::POST => auth_logout(aws, http_request).await,
            _ => method_not_allowed(),
        },
        "/auth/refresh" => match *method {
            Method::POST => auth_refresh(aws, http_request).await,
            _ => method_not_allowed(),
        },
        _ => not_found(),
    }
}

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

async fn get_aws() -> AWS {
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
    let users_table_name = get_stack_output(&stack, "UsersTableName");

    let cognito_identity_provider = cognitoidentityprovider::Client::new(&config);
    let user_pool_client = cognito_identity_provider
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
        users_table_name,
    }
}

struct AWS {
    reqwest: reqwest::Client,
    dynamodb: dynamodb::Client,
    s3: s3::Client,
    user_pool_client: UserPoolClientType,
    jwks: HashMap<String, DecodingKey>,
    api_gateway_management: apigatewaymanagement::Client,
    s3_bucket: String,
    user_pool_client_id: String,
    #[allow(dead_code)] // TODO
    function_cloudwatch_log_group: String,
    connections_table_name: String,
    users_table_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthState {
    connection_id: Option<String>,
}

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

async fn post_to_connection(aws: &AWS, connection_id: &str, data: &WebsocketServerMessage) {
    aws.api_gateway_management
        .post_to_connection()
        .connection_id(connection_id)
        .data(Blob::new(serde_json::to_string(data).unwrap()))
        .send()
        .await
        .unwrap();
}

async fn handle_websocket_message(aws: &AWS, connection_id: &str, body: &str) {
    match (
        serde_json::from_str::<WebsocketClientMessage>(body),
        get_connection(aws, connection_id).await,
    ) {
        (Ok(WebsocketClientMessage::LoginRequest {}), _) => {
            login_request(aws, connection_id).await;
        }
        (
            Ok(WebsocketClientMessage::Request {
                request_id,
                request: WebsocketClientRequest::GetPresignedUrl { object_path },
            }),
            Connection::Authorized { .. },
        ) => {
            let presigned_url = generate_presigned_url(aws, &object_path).await;
            post_to_connection(
                aws,
                connection_id,
                &WebsocketServerMessage::Response {
                    request_id,
                    response: WebsocketServerResponse::GetPresignedUrl {
                        url: presigned_url.url.to_string(),
                    },
                },
            )
            .await;
        }
        (
            Ok(WebsocketClientMessage::Request {
                request_id,
                request: WebsocketClientRequest::GetUser {},
            }),
            Connection::Authorized { user_id },
        ) => {
            let mut user = aws
                .dynamodb
                .get_item()
                .table_name(aws.users_table_name.as_str())
                .key("user_id", AttributeValue::S(user_id.to_string()))
                .send()
                .await
                .unwrap()
                .item
                .unwrap();
            let email = if let Some(AttributeValue::S(email)) = user.remove("email") {
                email
            } else {
                panic!("Expected email email address");
            };
            post_to_connection(
                aws,
                connection_id,
                &WebsocketServerMessage::Response {
                    request_id,
                    response: WebsocketServerResponse::GetUser {
                        user: User {
                            user_id: user_id.to_string(),
                            email,
                        },
                    },
                },
            )
            .await;
        }
        (Ok(WebsocketClientMessage::Request { request_id, .. }), Connection::Unauthorized) => {
            post_to_connection(
                aws,
                connection_id,
                &WebsocketServerMessage::Response {
                    request_id,
                    response: WebsocketServerResponse::Error {
                        error: WebsocketServerError::Unauthorized,
                    },
                },
            )
            .await;
        }
        (Err(err), _) => {
            println!("Error deserializing websocket message: {:?}", err);
        }
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct AccessTokenClaims {
    auth_time: i64,
    client_id: String,
    exp: i64,
    iat: i64,
    iss: String,
    jti: String,
    origin_jti: String,
    scope: String,
    pub sub: String,
    token_use: String,
    username: String,
    version: i64,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct IdTokenClaims {
    at_hash: String,
    aud: String,
    auth_time: i64,
    #[serde(rename = "cognito:username")]
    cognito_username: String,
    email: String,
    email_verified: bool,
    exp: i64,
    iat: i64,
    iss: String,
    jti: String,
    origin_jti: String,
    sub: String,
    token_use: String,
}

#[derive(Debug)]
enum TokenClaimsError {
    NoAuthorizationHeader,
    InvalidAuthorizationHeader,
    InvalidKid,
    JwtDecodeError,
}

struct Cookies {
    access_token: Option<String>,
    refresh_token: Option<String>,
}

fn get_cookies(headers: &HeaderMap) -> Cookies {
    let cookies = if let Some(cookies) = headers.get("cookie") {
        cookies
    } else {
        return Cookies {
            access_token: None,
            refresh_token: None,
        };
    };

    let mut access_token = None;
    let mut refresh_token = None;

    for cookie in cookie::Cookie::split_parse(cookies.to_str().unwrap()) {
        let cookie = if let Ok(cookie) = cookie {
            cookie
        } else {
            println!("Error parsing cookie");
            continue;
        };
        if cookie.name() == "accessToken" {
            access_token = Some(cookie.value().to_string());
        } else if cookie.name() == "refreshToken" {
            refresh_token = Some(cookie.value().to_string());
        }
    }

    Cookies {
        access_token,
        refresh_token,
    }
}

fn get_access_token_claims(
    aws: &AWS,
    headers: &HeaderMap,
) -> Result<AccessTokenClaims, TokenClaimsError> {
    // Get the accessToken cookie

    for cookie in cookie::Cookie::split_parse(
        headers
            .get("cookie")
            .ok_or(TokenClaimsError::NoAuthorizationHeader)?
            .to_str()
            .map_err(|_| TokenClaimsError::InvalidAuthorizationHeader)?,
    ) {
        let cookie = if let Ok(cookie) = cookie {
            cookie
        } else {
            println!("Error parsing cookie");
            continue;
        };
        if cookie.name() == "accessToken" {
            let jwt_token = cookie.value();
            return Ok(jwt::decode::<AccessTokenClaims>(
                jwt_token,
                get_decoding_key(aws, jwt_token)?,
                &Validation::new(RS256),
            )
            .map_err(|err| {
                println!("Error decoding JWT token: {:?}", err);
                TokenClaimsError::JwtDecodeError
            })?
            .claims);
        }
    }

    return Err(TokenClaimsError::NoAuthorizationHeader);
}

// fn get_access_token_claims(
//     aws: &AWS,
//     headers: &HeaderMap,
// ) -> Result<AccessTokenClaims, TokenClaimsError> {
//     // Get the `sub` claim from the JWT token passed in the `Authorization` header
//     let mut authorization_header_parts = headers
//         .get("authorization")
//         .ok_or(TokenClaimsError::NoAuthorizationHeader)?
//         .to_str()
//         .map_err(|_| TokenClaimsError::InvalidAuthorizationHeader)?
//         .split_whitespace();
//     let authorization_header_parts = (
//         authorization_header_parts.next(), // Scheme
//         authorization_header_parts.next(), // Parameter
//         authorization_header_parts.next(), // None
//     );

//     let jwt_token = match authorization_header_parts {
//         (Some("Bearer"), Some(jwt_token), None) => jwt_token,
//         _ => return Err(TokenClaimsError::InvalidAuthorizationHeader),
//     };

//     Ok(jwt::decode::<AccessTokenClaims>(
//         jwt_token,
//         get_decoding_key(aws, jwt_token)?,
//         &Validation::new(RS256),
//     )
//     .map_err(|err| {
//         println!("Error decoding JWT token: {:?}", err);
//         TokenClaimsError::JwtDecodeError
//     })?
//     .claims)
// }

fn get_decoding_key<'a>(
    aws: &'a AWS,
    jwt_token: &str,
) -> Result<&'a DecodingKey, TokenClaimsError> {
    let kid = jwt::decode_header(jwt_token)
        .map_err(|err| {
            println!("Error decoding JWT token header: {:?}", err);
            TokenClaimsError::JwtDecodeError
        })?
        .kid
        .ok_or(TokenClaimsError::InvalidKid)?;

    Ok(aws.jwks.get(&kid).ok_or(TokenClaimsError::InvalidKid)?)
}

fn get_id_token_claims(aws: &AWS, jwt_token: &str) -> Result<IdTokenClaims, TokenClaimsError> {
    Ok(
        jwt::decode::<IdTokenClaims>(jwt_token, get_decoding_key(aws, jwt_token)?, &{
            let mut validation = Validation::new(RS256);
            validation.set_audience(&[aws.user_pool_client_id.as_str()]);
            validation
        })
        .map_err(|err| {
            println!("Error decoding JWT token: {:?}", err);
            TokenClaimsError::JwtDecodeError
        })?
        .claims,
    )
}

enum Connection {
    Authorized { user_id: String },
    Unauthorized,
}

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

async fn handle_websocket_disconnect(aws: &AWS, connection_id: &str) {
    delete_connection(aws, connection_id).await;
}

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

struct PresignedUrl {
    url: Uri,
    #[allow(dead_code)]
    headers: HeaderMap,
}

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

#[tokio::main]
async fn main() {
    std::env::set_var("RUST_BACKTRACE", "full");

    lambda_main().await;
}
