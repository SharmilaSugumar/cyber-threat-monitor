import smtplib, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST  = os.getenv("SMTP_HOST",  "smtp.gmail.com")
SMTP_PORT  = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER  = os.getenv("SMTP_USER",  "your@gmail.com")
SMTP_PASS  = os.getenv("SMTP_PASS",  "your-app-password")
ALERT_TO   = os.getenv("ALERT_TO",   "admin@company.com")

def send_high_alert(log_text: str, explanation: list, score: float, ips: list):
    """Send email when HIGH severity threat detected."""
    if not SMTP_USER or SMTP_USER == "your@gmail.com":
        print("⚠️  Email not configured — skipping alert email")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🚨 HIGH Severity Threat Detected — Score {score}"
    msg["From"]    = SMTP_USER
    msg["To"]      = ALERT_TO

    html = f"""
    <html><body style="font-family:sans-serif;background:#0d0d1a;color:#e8e8ff;padding:24px">
      <h2 style="color:#f87171">HIGH Severity Threat Detected</h2>
      <p><strong>Score:</strong> {score}</p>
      <p><strong>Log:</strong> <code style="background:#1a1a35;padding:4px 8px;border-radius:4px">{log_text[:300]}</code></p>
      <p><strong>Suspicious IPs:</strong> {', '.join(ips) or 'None'}</p>
      <h3>Reasons:</h3>
      <ul>{''.join(f"<li>{r}</li>" for r in explanation)}</ul>
      <p style="color:#9d8ec7;font-size:12px">CyberAI Monitor — automated alert</p>
    </body></html>
    """
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_TO, msg.as_string())
        print(f"✅ Alert email sent to {ALERT_TO}")
    except Exception as e:
        print(f"❌ Email failed: {e}")