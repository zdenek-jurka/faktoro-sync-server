use crate::error::AppError;
use crate::payloads::{encode_recovery_payload_pem, RecoveryPayload};
use base64::Engine;
use image::{DynamicImage, ImageFormat, Luma};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use qrcode::QrCode;
use std::io::Cursor;
use std::env;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct MailerConfig {
    pub transport: AsyncSmtpTransport<Tokio1Executor>,
    pub from: Mailbox,
}

enum SmtpSecurity {
    StartTls,
    Tls,
    Plain,
}

impl SmtpSecurity {
    fn from_env(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "starttls" => Ok(Self::StartTls),
            "tls" | "smtps" | "ssl" => Ok(Self::Tls),
            "plain" | "none" => Ok(Self::Plain),
            _ => Err(anyhow::anyhow!(
                "Invalid SMTP_SECURITY value: '{value}'. Use one of: starttls, tls, plain"
            )),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::StartTls => "starttls",
            Self::Tls => "tls",
            Self::Plain => "plain",
        }
    }
}

pub fn build_mailer_from_env() -> anyhow::Result<MailerConfig> {
    let smtp_host = env::var("SMTP_HOST")?;
    let smtp_port: u16 = env::var("SMTP_PORT")?.parse()?;
    let smtp_username = env::var("SMTP_USERNAME").unwrap_or_default();
    let smtp_password = env::var("SMTP_PASSWORD").unwrap_or_default();
    let smtp_security = SmtpSecurity::from_env(
        &env::var("SMTP_SECURITY").unwrap_or_else(|_| "starttls".to_string()),
    )?;
    let smtp_from = env::var("SMTP_FROM")?;
    let from: Mailbox = smtp_from.parse()?;
    let builder = match smtp_security {
        SmtpSecurity::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_host)?,
        SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp_host)?,
        SmtpSecurity::Plain => {
            warn!("SMTP_SECURITY=plain: credentials and emails will be sent without encryption");
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp_host)
        }
    };

    let smtp_auth_enabled = !smtp_username.trim().is_empty();
    let mut builder = builder.port(smtp_port);
    if smtp_auth_enabled {
        builder = builder.credentials(Credentials::new(smtp_username, smtp_password));
    }

    info!(
        smtp_host = %smtp_host,
        smtp_port = smtp_port,
        smtp_security = smtp_security.as_str(),
        smtp_auth = if smtp_auth_enabled { "enabled" } else { "disabled" },
        "Mailer SMTP configuration loaded"
    );

    let transport = builder.build();

    Ok(MailerConfig { transport, from })
}

pub async fn send_recovery_email(
    mailer: &MailerConfig,
    instance_id: &str,
    device_id: &str,
    device_name: &str,
    recipient_email: &str,
    recovery_token: &str,
    server_base_url: &str,
) -> Result<(), AppError> {
    let recovery_payload = encode_recovery_payload_pem(&RecoveryPayload {
        instance_id: instance_id.to_string(),
        device_id: device_id.to_string(),
        recovery_token: recovery_token.to_string(),
        server_base_url: server_base_url.to_string(),
    })
    .ok_or_else(|| AppError::bad_request("Failed to build recovery payload"))?;

    let recovery_qr_png_base64 = build_recovery_qr_png_base64(&recovery_payload)?;

    let to_mailbox: Mailbox = recipient_email
        .parse()
        .map_err(|_| AppError::bad_request("Invalid recovery email"))?;

    let subject = format!("Faktoro recovery code for device {}", device_name);
    let text_body = format!(
        "Recovery code for device '{}'.\n\nQR code is shown inline in this email.\n\nUse this recovery payload in the app:\n{}\n",
        device_name, recovery_payload
    );
    let escaped_name = escape_html(device_name);
    let escaped_payload = escape_html(&recovery_payload);
    let html_body = format!(
        "<p>Recovery code for device <strong>{}</strong>.</p>\
         <p>Keep this email for restoring access when device is lost.</p>\
         <p><img alt=\"Faktoro recovery QR\" src=\"data:image/png;base64,{}\" /></p>\
         <p>Use this recovery payload in the app:</p><pre>{}</pre>",
        escaped_name, recovery_qr_png_base64, escaped_payload
    );

    let message = Message::builder()
        .from(mailer.from.clone())
        .to(to_mailbox)
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::plain(text_body))
                .singlepart(SinglePart::html(html_body)),
        )
        .map_err(|_| AppError::bad_request("Failed to build recovery email"))?;

    mailer
        .transport
        .send(message)
        .await
        .map_err(|error| {
            error!("Failed to send recovery email: {error}");
            AppError::internal_message("Failed to send recovery email")
        })?;

    Ok(())
}

fn build_recovery_qr_png_base64(payload: &str) -> Result<String, AppError> {
    let qr = QrCode::new(payload.as_bytes())
        .map_err(|_| AppError::bad_request("Failed to build recovery QR code"))?;
    let image = qr.render::<Luma<u8>>().min_dimensions(420, 420).build();
    let mut png_bytes = Vec::new();
    DynamicImage::ImageLuma8(image)
        .write_to(&mut Cursor::new(&mut png_bytes), ImageFormat::Png)
        .map_err(|_| AppError::internal_message("Failed to encode recovery QR as PNG"))?;
    let base64_png = base64::engine::general_purpose::STANDARD.encode(png_bytes);

    Ok(base64_png)
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
