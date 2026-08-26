use crate::models::xbox::{
    UserAuthProperties, UserAuthRequest, XstsPropertyBag, XstsRequest, XstsResponse,
};
use serde::{Serialize, de::DeserializeOwned};

const MAX_XBOX_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum XboxApiError {
    #[error("xbox request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("xbox response body is {size} bytes, exceeding the limit {limit}")]
    ResponseBodyTooLarge { size: usize, limit: usize },
    #[error("xbox response body allocation failed at {size} bytes, limit {limit}")]
    ResponseBodyAllocationFailed { size: usize, limit: usize },
    #[error("xbox response is not valid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("xbox request redirected to an insecure scheme")]
    InsecureRedirect,
}

async fn post_json<Body, Response>(
    client: &reqwest::Client,
    endpoint: &str,
    body: &Body,
) -> Result<Response, XboxApiError>
where
    Body: Serialize,
    Response: DeserializeOwned,
{
    let request_url = reqwest::Url::parse(endpoint).map_err(|_| XboxApiError::InsecureRedirect)?;
    let response = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(body)
        .send()
        .await?;
    crate::api::ensure_response_scheme(&request_url, response.url())
        .map_err(|_| XboxApiError::InsecureRedirect)?;
    let response = response.error_for_status()?;
    decode_json_response(response).await
}

fn validate_json_response_length(content_length: Option<u64>) -> Result<(), XboxApiError> {
    let Some(length) = content_length else {
        return Ok(());
    };
    if length > MAX_XBOX_JSON_RESPONSE_BYTES as u64 {
        return Err(XboxApiError::ResponseBodyTooLarge {
            size: usize::try_from(length).unwrap_or(usize::MAX),
            limit: MAX_XBOX_JSON_RESPONSE_BYTES,
        });
    }
    Ok(())
}

fn append_json_response_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), XboxApiError> {
    let next_size =
        body.len()
            .checked_add(chunk.len())
            .ok_or(XboxApiError::ResponseBodyTooLarge {
                size: usize::MAX,
                limit: MAX_XBOX_JSON_RESPONSE_BYTES,
            })?;
    if next_size > MAX_XBOX_JSON_RESPONSE_BYTES {
        return Err(XboxApiError::ResponseBodyTooLarge {
            size: next_size,
            limit: MAX_XBOX_JSON_RESPONSE_BYTES,
        });
    }
    body.try_reserve(chunk.len())
        .map_err(|_| XboxApiError::ResponseBodyAllocationFailed {
            size: next_size,
            limit: MAX_XBOX_JSON_RESPONSE_BYTES,
        })?;
    body.extend_from_slice(chunk);
    Ok(())
}

pub async fn decode_json_response<Response>(
    mut response: reqwest::Response,
) -> Result<Response, XboxApiError>
where
    Response: DeserializeOwned,
{
    validate_json_response_length(response.content_length())?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_json_response_chunk(&mut body, &chunk)?;
    }
    Ok(serde_json::from_slice(&body)?)
}

pub async fn authenticate_xbox_user(
    client: &reqwest::Client,
    rps_ticket: String,
) -> Result<XstsResponse, XboxApiError> {
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
) -> Result<XstsResponse, XboxApiError> {
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

    use super::{
        XboxApiError, append_json_response_chunk, get_xsts_auth_header, post_json,
        validate_json_response_length,
    };
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

        let XboxApiError::Request(error) = result.expect_err("non-success status must fail") else {
            panic!("non-success status must remain a request error");
        };
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

        assert!(matches!(result, Err(XboxApiError::Json(_))));
        server.await.expect("test server must exit");
    }

    #[test]
    fn oversized_xbox_response_length_is_rejected_before_json_decode() {
        assert!(matches!(
            validate_json_response_length(Some((super::MAX_XBOX_JSON_RESPONSE_BYTES as u64) + 1)),
            Err(XboxApiError::ResponseBodyTooLarge { .. })
        ));
    }

    #[test]
    fn oversized_xbox_chunk_is_rejected_before_json_decode() {
        let mut body = vec![0_u8; super::MAX_XBOX_JSON_RESPONSE_BYTES];

        assert!(matches!(
            append_json_response_chunk(&mut body, &[0]),
            Err(XboxApiError::ResponseBodyTooLarge { .. })
        ));
    }
}
