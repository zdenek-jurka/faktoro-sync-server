use crate::error::AppError;
use crate::payloads::PairBootstrapPayload;
use axum::extract::Query;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use image::{DynamicImage, ImageFormat, Luma};
use qrcode::QrCode;
use serde::Deserialize;
use std::env;
use std::io::Cursor;

#[derive(Debug, Deserialize)]
pub struct PairQrQuery {
    pub payload: String,
}

#[derive(Debug, serde::Serialize)]
pub struct PairBootstrapResponse {
    pub payload: String,
    pub pairing_init_url: String,
    pub server_base_url: String,
}

pub async fn pair_bootstrap(headers: HeaderMap) -> Result<Json<PairBootstrapResponse>, AppError> {
    let server_base_url = resolve_server_base_url(&headers);
    let pairing_init_url = format!("{server_base_url}/api/pairing/init");
    let payload = serde_json::to_string(&PairBootstrapPayload {
        kind: "faktoro_pair_bootstrap_v1".to_string(),
        pairing_init_url: pairing_init_url.clone(),
        server_base_url: server_base_url.clone(),
    })
    .map_err(|e| AppError::internal_message(e.to_string()))?;

    Ok(Json(PairBootstrapResponse {
        payload,
        pairing_init_url,
        server_base_url,
    }))
}

pub async fn pair_qr(Query(query): Query<PairQrQuery>) -> Result<Response, AppError> {
    if query.payload.trim().is_empty() {
        return Err(AppError::bad_request("QR payload cannot be empty"));
    }
    if query.payload.len() > 8192 {
        return Err(AppError::bad_request("QR payload is too large"));
    }

    let qr = QrCode::new(query.payload.as_bytes())
        .map_err(|_| AppError::bad_request("Invalid QR payload"))?;
    let image = qr.render::<Luma<u8>>().min_dimensions(420, 420).build();

    let mut png_bytes = Vec::new();
    DynamicImage::ImageLuma8(image)
        .write_to(&mut Cursor::new(&mut png_bytes), ImageFormat::Png)
        .map_err(|_| AppError::internal_message("Failed to build QR PNG"))?;

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "image/png".parse().unwrap());
    Ok((StatusCode::OK, headers, png_bytes).into_response())
}

fn resolve_server_base_url(headers: &HeaderMap) -> String {
    if let Ok(public_base_url) = env::var("PUBLIC_BASE_URL") {
        let trimmed = public_base_url.trim().trim_end_matches('/').to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    let forwarded_proto = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");
    let forwarded_host = headers
        .get("x-forwarded-host")
        .and_then(|h| h.to_str().ok())
        .or_else(|| headers.get(header::HOST).and_then(|h| h.to_str().ok()))
        .unwrap_or("localhost:8080");

    format!("{forwarded_proto}://{forwarded_host}")
}

#[cfg(test)]
mod tests {
    use super::pair_qr;
    use super::{pair_bootstrap, PairQrQuery};
    use axum::extract::Query;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn pair_bootstrap_returns_ok() {
        let response = pair_bootstrap(HeaderMap::new()).await.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn pair_qr_returns_png() {
        let response = pair_qr(Query(PairQrQuery {
            payload: "hello".to_string(),
        }))
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
