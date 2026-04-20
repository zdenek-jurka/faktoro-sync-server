use crate::error::AppError;
use axum::extract::Query;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use image::{DynamicImage, ImageFormat, Luma};
use qrcode::QrCode;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Debug, Deserialize)]
pub struct PairQrQuery {
    pub payload: String,
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

#[cfg(test)]
mod tests {
    use super::{pair_qr, PairQrQuery};
    use axum::extract::Query;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

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
