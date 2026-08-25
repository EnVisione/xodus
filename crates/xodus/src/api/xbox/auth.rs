use crate::models::xbox::{
    UserAuthProperties, UserAuthRequest, XstsPropertyBag, XstsRequest, XstsResponse,
};
use serde::{Serialize, de::DeserializeOwned};

async fn post_json<Body, Response>(
    client: &reqwest::Client,
    endpoint: &str,
    body: &Body,
) -> reqwest::Result<Response>
where
    Body: Serialize,
    Response: DeserializeOwned,
{
    client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

pub async fn authenticate_xbox_user(
    client: &reqwest::Client,
    rps_ticket: String,
) -> reqwest::Result<XstsResponse> {
    let body = UserAuthRequest {
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
        properties: UserAuthProperties {
            auth_method: "RPS".to_string(),
            site_name: "user.auth.xboxlive.com".to_string(),
            rps_ticket,
        },
    };

    post_json(
        client,
        "https://user.auth.xboxlive.com/user/authenticate",
        &body,
    )
    .await
}

pub async fn request_xsts_token(
    client: &reqwest::Client,
    token: String,
    relying_party: &str,
) -> reqwest::Result<XstsResponse> {
    let body = XstsRequest {
        relying_party: Some(relying_party.to_string()),
        token_type: Some("JWT".to_string()),
        properties: XstsPropertyBag {
            user_tokens: Some(vec![token]),
            sandbox_id: Some("RETAIL".to_string()),
            delegation_token: None,
            service_token: None,
        },
    };

    post_json(
        client,
        "https://xsts.auth.xboxlive.com/xsts/authorize",
        &body,
    )
    .await
}

pub fn get_xsts_auth_header(xsts: XstsResponse) -> Result<String, std::io::Error> {
    if xsts.token.is_empty() {
        return Err(std::io::Error::other("XSTS response missing token"));
    }
    let uhs = xsts
        .user_hash()
        .filter(|hash| !hash.is_empty())
        .ok_or_else(|| std::io::Error::other("XSTS response missing xui claim"))?;
    Ok(format!("XBL3.0 x={uhs};{}", xsts.token))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{get_xsts_auth_header, post_json};
    use crate::models::xbox::XstsResponse;

    async fn response_server(status: &str, body: &str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must be available");
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        (format!("http://{address}/response"), handle)
    }

    #[test]
    fn xsts_header_rejects_missing_user_claim() {
        let response: XstsResponse = serde_json::from_str(
            r#"{
                "NotAfter":"2026-01-01T00:00:00Z",
                "Token":"token",
                "DisplayClaims":{"Xui":[],"Xti":[]}
            }"#,
        )
        .expect("synthetic XSTS response must deserialize");

        assert!(get_xsts_auth_header(response).is_err());
    }

    #[test]
    fn xsts_header_rejects_empty_token() {
        let response: XstsResponse = serde_json::from_str(
            r#"{
                "NotAfter":"2026-01-01T00:00:00Z",
                "Token":"",
                "DisplayClaims":{"Xui":[{"Uhs":"user"}],"Xti":[]}
            }"#,
        )
        .expect("synthetic XSTS response must deserialize");

        assert!(get_xsts_auth_header(response).is_err());
    }

    #[test]
    fn xsts_header_rejects_empty_user_hash() {
        let response: XstsResponse = serde_json::from_str(
            r#"{
                "NotAfter":"2026-01-01T00:00:00Z",
                "Token":"token",
                "DisplayClaims":{"Xui":[{"Uhs":""}],"Xti":[]}
            }"#,
        )
        .expect("synthetic XSTS response must deserialize");

        assert!(get_xsts_auth_header(response).is_err());
    }

    #[tokio::test]
    async fn xbox_http_status_is_returned_as_a_request_error() {
        let (endpoint, server) = response_server("503 Service Unavailable", "{}").await;
        let result = post_json::<_, serde_json::Value>(
            &reqwest::Client::new(),
            &endpoint,
            &serde_json::json!({}),
        )
        .await;

        let error = result.expect_err("non-success status must fail");
        assert_eq!(
            error.status(),
            Some(reqwest::StatusCode::SERVICE_UNAVAILABLE)
        );
        server.await.expect("test server must exit");
    }

    #[tokio::test]
    async fn xbox_schema_failure_is_returned_as_a_decode_error() {
        let (endpoint, server) = response_server("200 OK", "{\"unexpected\":true}").await;
        let result = post_json::<_, XstsResponse>(
            &reqwest::Client::new(),
            &endpoint,
            &serde_json::json!({}),
        )
        .await;

        assert!(result.is_err(), "missing required XSTS fields must fail");
        server.await.expect("test server must exit");
    }
}
