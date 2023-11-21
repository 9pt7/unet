// use aws_config;
// use aws_sdk_ecr;
// use base64;
// use base64::Engine as _;
// use tokio::process::Command;

// struct EcrCredentials {
//     username: String,
//     password: String,
// }

// async fn get_ecr_credentials() -> EcrCredentials {
//     let config = aws_config::load_from_env().await;
//     let ecr = aws_sdk_ecr::Client::new(&config);

//     let get_authorization_data = ecr
//         .get_authorization_token()
//         .send()
//         .await
//         .unwrap()
//         .authorization_data
//         .unwrap();

//     let authorization_token_base64 = get_authorization_data[0]
//         .authorization_token
//         .as_ref()
//         .unwrap();

//     let authorization_token = String::from_utf8(
//         base64::engine::general_purpose::STANDARD
//             .decode(&authorization_token_base64)
//             .unwrap(),
//     )
//     .unwrap();

//     let username_password_vec = authorization_token.split(":").collect::<Vec<&str>>();
//     let username = username_password_vec[0];
//     let password = username_password_vec[1];

//     EcrCredentials {
//         username: String::from(username),
//         password: String::from(password),
//     }
// }

// async fn docker_login() {
//     let ecr_credentials = get_ecr_credentials().await;
//     let username = ecr_credentials.username;
//     let password = ecr_credentials.password;

//     let docker_login_command = Command::new("docker")
//         .arg("login")
//         .arg("-u")
//         .arg(username)
//         .arg("-p")
//         .arg(password)
//         .arg("https://aws_account_id.dkr.ecr.region.amazonaws.com")
//         .output()
//         .await
//         .unwrap();
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_get_ecr_credentials() {
//         let credentials = get_ecr_credentials().await;
//         assert_eq!(2 + 2, 4);
//     }
// }
