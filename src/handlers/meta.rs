use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Html;
use axum::Json;
use std::env;

const OPENAPI_YAML_TEMPLATE: &str = include_str!("../../openapi.yaml");
const OPENAPI_PUBLIC_BASE_URL_PLACEHOLDER: &str = "__PUBLIC_BASE_URL__";

pub async fn root() -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "faktoro-sync-server",
        "status": "ok",
        "docs": "/docs",
        "openapi": "/openapi.yaml"
    }))
}

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

pub async fn docs_index() -> Html<&'static str> {
    Html(include_str!("../../static/docs/index.html"))
}

pub async fn openapi_yaml() -> impl IntoResponse {
    let public_base_url = env::var("PUBLIC_BASE_URL")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "http://localhost:8080".to_string());
    let openapi_yaml =
        OPENAPI_YAML_TEMPLATE.replace(OPENAPI_PUBLIC_BASE_URL_PLACEHOLDER, &public_base_url);

    (
        [(header::CONTENT_TYPE, "application/yaml; charset=utf-8")],
        openapi_yaml,
    )
}

#[cfg(test)]
mod tests {
    use super::{health, root};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn root_endpoint_returns_ok() {
        let response = root().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let response = health().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
