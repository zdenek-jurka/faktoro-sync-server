use serde::{Deserialize, Serialize};
use base64::Engine;
use std::borrow::Cow;

const PAIRING_KIND_V1: &str = "faktoro_device_pairing_v1";
const RECOVERY_PAYLOAD_PEM_BEGIN: &str = "-----BEGIN FAKTORO RECOVERY PAYLOAD-----";
const RECOVERY_PAYLOAD_PEM_END: &str = "-----END FAKTORO RECOVERY PAYLOAD-----";
const RECOVERY_PEM_LINE_WIDTH: usize = 64;

#[derive(Debug, Deserialize)]
pub struct PairingPayload {
    pub kind: String,
    #[serde(rename = "instanceId")]
    pub instance_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub token: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(rename = "recoveryEmail")]
    pub recovery_email: String,
    #[serde(rename = "serverBaseUrl", default)]
    #[allow(dead_code)]
    pub server_base_url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RecoveryPayload {
    #[serde(rename = "instanceId", default, skip_serializing_if = "String::is_empty")]
    pub instance_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "recoveryToken")]
    pub recovery_token: String,
    #[serde(rename = "serverBaseUrl", default, skip_serializing_if = "String::is_empty")]
    pub server_base_url: String,
}

pub fn parse_pairing_payload(raw: &str) -> Option<PairingPayload> {
    let payload = serde_json::from_str::<PairingPayload>(raw).ok()?;
    if payload.kind == PAIRING_KIND_V1 {
        Some(payload)
    } else {
        None
    }
}

pub fn parse_recovery_payload(raw: &str) -> Option<RecoveryPayload> {
    let trimmed = extract_payload_candidate(raw);
    if let Ok(payload) = serde_json::from_str::<RecoveryPayload>(trimmed.as_ref()) {
        return Some(payload);
    }

    let decoded_json = decode_recovery_payload_pem(trimmed.as_ref())?;
    serde_json::from_str::<RecoveryPayload>(&decoded_json).ok()
}

pub fn encode_recovery_payload_pem(payload: &RecoveryPayload) -> Option<String> {
    let json_payload = serde_json::to_vec(payload).ok()?;
    let base64_payload = base64::engine::general_purpose::STANDARD.encode(json_payload);

    let mut wrapped = String::with_capacity(base64_payload.len() + 64);
    let mut start = 0;
    while start < base64_payload.len() {
        let end = (start + RECOVERY_PEM_LINE_WIDTH).min(base64_payload.len());
        wrapped.push_str(&base64_payload[start..end]);
        wrapped.push('\n');
        start = end;
    }

    Some(format!(
        "{RECOVERY_PAYLOAD_PEM_BEGIN}\n{wrapped}{RECOVERY_PAYLOAD_PEM_END}"
    ))
}

fn decode_recovery_payload_pem(raw: &str) -> Option<String> {
    if !raw.contains(RECOVERY_PAYLOAD_PEM_BEGIN) || !raw.contains(RECOVERY_PAYLOAD_PEM_END) {
        return None;
    }

    let body = raw
        .replace(RECOVERY_PAYLOAD_PEM_BEGIN, "")
        .replace(RECOVERY_PAYLOAD_PEM_END, "");
    let compact_base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if compact_base64.is_empty() {
        return None;
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(compact_base64)
        .ok()?;
    String::from_utf8(decoded).ok()
}

fn extract_payload_candidate<'a>(raw: &'a str) -> Cow<'a, str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Cow::Borrowed(trimmed);
    }

    extract_payload_query_value(trimmed).unwrap_or_else(|| Cow::Borrowed(trimmed))
}

fn extract_payload_query_value(raw: &str) -> Option<Cow<'_, str>> {
    let (_, query) = raw.split_once('?')?;
    for segment in query.split('&') {
        let (key, value) = segment.split_once('=')?;
        if key == "payload" {
            return Some(match percent_decode_to_owned(value) {
                Some(decoded) => Cow::Owned(decoded),
                None => Cow::Borrowed(value),
            });
        }
    }
    None
}

fn percent_decode_to_owned(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut changed = false;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let high = decode_hex(bytes[index + 1])?;
                let low = decode_hex(bytes[index + 2])?;
                output.push((high << 4) | low);
                index += 3;
                changed = true;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
                changed = true;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }

    if !changed {
        return None;
    }

    String::from_utf8(output).ok()
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_recovery_payload_pem, parse_recovery_payload, RecoveryPayload};

    #[test]
    fn recovery_payload_round_trip_pem() {
        let payload = RecoveryPayload {
            instance_id: "inst-1".to_string(),
            device_id: "dev-1".to_string(),
            recovery_token: "token-1".to_string(),
            server_base_url: "https://example.com".to_string(),
        };

        let pem = encode_recovery_payload_pem(&payload).expect("encode");
        let parsed = parse_recovery_payload(&pem).expect("parse");

        assert_eq!(parsed.device_id, "dev-1");
        assert_eq!(parsed.recovery_token, "token-1");
    }

    #[test]
    fn recovery_payload_parses_from_url_payload_query() {
        let raw = "https://sync.example.com/recover?payload=%7B%22deviceId%22%3A%22dev-1%22%2C%22recoveryToken%22%3A%22token-1%22%2C%22serverBaseUrl%22%3A%22https%3A%2F%2Fsync.example.com%22%7D";

        let parsed = parse_recovery_payload(raw).expect("parse");

        assert_eq!(parsed.device_id, "dev-1");
        assert_eq!(parsed.recovery_token, "token-1");
        assert_eq!(parsed.server_base_url, "https://sync.example.com");
    }
}
