use serde::{Deserialize, Serialize};
use base64::Engine;

const PAIRING_KIND_V1: &str = "faktoro_device_pairing_v1";
const RECOVERY_PAYLOAD_PEM_BEGIN: &str = "-----BEGIN FAKTORO RECOVERY PAYLOAD-----";
const RECOVERY_PAYLOAD_PEM_END: &str = "-----END FAKTORO RECOVERY PAYLOAD-----";
const RECOVERY_PEM_LINE_WIDTH: usize = 64;

#[derive(Debug, Serialize, Deserialize)]
pub struct PairBootstrapPayload {
    pub kind: String,
    #[serde(rename = "pairingInitUrl")]
    pub pairing_init_url: String,
    #[serde(rename = "serverBaseUrl")]
    pub server_base_url: String,
}

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
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RecoveryPayload {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "recoveryToken")]
    pub recovery_token: String,
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
    let trimmed = raw.trim();
    if let Ok(payload) = serde_json::from_str::<RecoveryPayload>(trimmed) {
        return Some(payload);
    }

    let decoded_json = decode_recovery_payload_pem(trimmed)?;
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

#[cfg(test)]
mod tests {
    use super::{encode_recovery_payload_pem, parse_recovery_payload, RecoveryPayload};

    #[test]
    fn recovery_payload_round_trip_pem() {
        let payload = RecoveryPayload {
            device_id: "dev-1".to_string(),
            recovery_token: "token-1".to_string(),
        };

        let pem = encode_recovery_payload_pem(&payload).expect("encode");
        let parsed = parse_recovery_payload(&pem).expect("parse");

        assert_eq!(parsed.device_id, "dev-1");
        assert_eq!(parsed.recovery_token, "token-1");
    }
}
