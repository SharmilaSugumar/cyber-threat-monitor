"""
notification_service.py
Handles email alerts (Gmail SMTP) and SMS alerts (Twilio).
Both are optional — if not configured they are silently skipped.
"""
import os, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Email config (from .env) ───────────────────────────────────────────────────
SMTP_HOST = os.getenv("SMTP_HOST",  "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER",  "")
SMTP_PASS = os.getenv("SMTP_PASS",  "")

# ── Twilio config (from .env) ──────────────────────────────────────────────────
TWILIO_SID   = os.getenv("TWILIO_ACCOUNT_SID",  "")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN",    "")
TWILIO_FROM  = os.getenv("TWILIO_FROM_NUMBER",   "")  # e.g. +15005550006

SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _should_notify(alert_severity: str, min_severity: str) -> bool:
    """Return True if alert severity meets the user's minimum threshold."""
    return SEV_RANK.get(alert_severity, 0) >= SEV_RANK.get(min_severity, 3)


def send_email_alert(
    to_email:    str,
    username:    str,
    severity:    str,
    score:       float,
    log_text:    str,
    explanation: list,
    ips:         list,
):
    """Send an HTML email alert to the user."""
    if not SMTP_USER or not SMTP_PASS:
        print("⚠️  Email not configured — skipping")
        return

    sev_color = {"HIGH": "#f87171", "MEDIUM": "#fbbf24", "LOW": "#34d399"}.get(severity, "#8b5cf6")

    html = f"""
    <html>
    <body style="font-family:sans-serif;background:#0d0d1a;color:#e8e8ff;padding:28px;margin:0">
      <div style="max-width:520px;margin:0 auto">
        <div style="background:linear-gradient(135deg,#8b5cf6,#ec4899);
          padding:20px 24px;border-radius:12px 12px 0 0">
          <h1 style="margin:0;font-size:20px;color:#fff">
            CyberAI Monitor — Threat Alert
          </h1>
        </div>
        <div style="background:#13132b;padding:24px;border-radius:0 0 12px 12px;
          border:1px solid #2a2550;border-top:none">

          <p style="margin:0 0 16px;font-size:14px">
            Hi <strong>{username}</strong>, a threat was detected on your system.
          </p>

          <div style="background:#1a1a35;border-radius:8px;padding:16px;margin-bottom:16px">
            <div style="display:flex;justify-content:space-between;align-items:center;
              margin-bottom:12px">
              <span style="font-size:13px;color:#9d8ec7">Severity</span>
              <span style="background:{sev_color}22;color:{sev_color};
                padding:4px 12px;border-radius:20px;font-size:12px;
                font-weight:700;border:1px solid {sev_color}44">
                {severity}
              </span>
            </div>
            <div style="display:flex;justify-content:space-between;margin-bottom:8px">
              <span style="font-size:13px;color:#9d8ec7">Score</span>
              <span style="font-size:13px;font-family:monospace;color:{sev_color}">{score}</span>
            </div>
            {f'<div style="display:flex;justify-content:space-between"><span style="font-size:13px;color:#9d8ec7">IPs</span><span style="font-size:13px;font-family:monospace;color:#fbbf24">{", ".join(ips)}</span></div>' if ips else ""}
          </div>

          <div style="background:#1a1a35;border-radius:8px;padding:14px;margin-bottom:16px">
            <p style="margin:0 0 8px;font-size:12px;color:#9d8ec7;
              font-family:monospace;text-transform:uppercase">Log</p>
            <p style="margin:0;font-size:12px;font-family:monospace;
              color:#ede9fe;word-break:break-all">{log_text[:200]}</p>
          </div>

          <div style="background:#1a1a35;border-radius:8px;padding:14px">
            <p style="margin:0 0 10px;font-size:12px;color:#9d8ec7;
              font-family:monospace;text-transform:uppercase">Why flagged</p>
            {''.join(f'<div style="padding:6px 10px;background:#0f0f2a;border-radius:6px;margin-bottom:6px;font-size:12px;border-left:3px solid #8b5cf6">{r}</div>' for r in explanation)}
          </div>

          <p style="margin:20px 0 0;font-size:11px;color:#5a4f7a;text-align:center">
            CyberAI Monitor — automated threat notification<br>
            To stop these alerts, update your preferences in the dashboard.
          </p>
        </div>
      </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[CyberAI] {severity} Threat Detected — Score {score}"
    msg["From"]    = SMTP_USER
    msg["To"]      = to_email
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        print(f"✅ Email alert sent to {to_email}")
    except Exception as e:
        print(f"❌ Email failed: {e}")


def send_sms_alert(
    to_phone:  str,
    severity:  str,
    score:     float,
    log_text:  str,
    ips:       list,
):
    """Send an SMS alert via Twilio."""
    if not TWILIO_SID or not TWILIO_TOKEN or not TWILIO_FROM:
        print("⚠️  Twilio not configured — skipping SMS")
        return

    try:
        from twilio.rest import Client
        client  = Client(TWILIO_SID, TWILIO_TOKEN)
        ip_text = f" IPs: {', '.join(ips[:2])}" if ips else ""
        body    = (
            f"[CyberAI Alert]\n"
            f"Severity: {severity} (score: {score})\n"
            f"{ip_text}\n"
            f"Log: {log_text[:80]}...\n"
            f"Check your dashboard for details."
        )
        client.messages.create(to=to_phone, from_=TWILIO_FROM, body=body)
        print(f"✅ SMS alert sent to {to_phone}")
    except ImportError:
        print("⚠️  twilio package not installed. Run: pip install twilio")
    except Exception as e:
        print(f"❌ SMS failed: {e}")


def notify_user(user, analysis: dict):
    """
    Main function — called after every anomaly is saved.
    Checks user preferences and sends email/SMS if configured.
    """
    severity    = analysis["severity"]["level"]
    score       = analysis["severity"]["score"]
    log_text    = analysis.get("text", "")[:200]
    explanation = analysis.get("explanation", [])
    ips         = analysis["entities"].get("ips", [])

    # Check minimum severity threshold
    if not _should_notify(severity, user.notify_min_severity or "HIGH"):
        return

    # Send email
    if user.notify_email and user.email:
        send_email_alert(
            to_email    = user.email,
            username    = user.full_name or user.username,
            severity    = severity,
            score       = score,
            log_text    = log_text,
            explanation = explanation,
            ips         = ips,
        )

    # Send SMS
    if user.notify_sms and user.notify_phone:
        send_sms_alert(
            to_phone = user.notify_phone,
            severity = severity,
            score    = score,
            log_text = log_text,
            ips      = ips,
        )