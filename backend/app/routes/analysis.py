from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
import json, io, csv, datetime

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as rl_canvas

from ..database import get_db
from ..models.models import Alert, User
from ..services.detection_engine import HybridDetectionEngine
from ..services.preprocessor import LogPreprocessor
from ..services.notification_service import notify_user
from ..services.training_data import get_training_data
from ..routes.auth import get_current_user

router       = APIRouter()
engine       = HybridDetectionEngine()
preprocessor = LogPreprocessor()


class TextPayload(BaseModel):
    text: str


# ── Save alert + send notifications ──────────────────────────────────────────
def _save_alert(db: Session, analysis: dict, source: str, user: User):
    if not analysis["is_anomaly"]:
        return

    a = Alert(
        log_text       = analysis.get("text", "")[:500],
        severity       = analysis["severity"]["level"],
        severity_score = analysis["severity"]["score"],
        is_anomaly     = 1,
        explanation    = json.dumps(analysis["explanation"]),
        ip_addresses   = ", ".join(analysis["entities"]["ips"]),
        usernames      = ", ".join(analysis["entities"]["users"]),
        ml_confidence  = analysis["ml_prediction"]["confidence"],
        rule_score     = analysis["rule_analysis"]["rule_score"],
        source         = source,
        user_id        = user.id,
    )
    db.add(a)
    db.commit()

    # Send email/SMS based on user preferences
    notify_user(user, analysis)


# ── Analyze single text ───────────────────────────────────────────────────────
@router.post("/analyze/text")
def analyze_text(
    payload:      TextPayload,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    result = engine.analyze(payload.text)
    result["text"] = payload.text
    _save_alert(db, result, "manual", current_user)
    return result


# ── Analyze uploaded file ─────────────────────────────────────────────────────
@router.post("/analyze/upload")
async def analyze_upload(
    file:         UploadFile = File(...),
    db:           Session    = Depends(get_db),
    current_user: User       = Depends(get_current_user),
):
    content = await file.read()
    raw     = content.decode("utf-8", errors="ignore")
    logs    = preprocessor.process_text(raw)

    if not logs:
        raise HTTPException(status_code=400, detail="No parseable logs found in file")

    sequences = preprocessor.build_sequences(logs)
    results   = []

    for seq in sequences:
        analysis         = engine.analyze(seq["text"])
        analysis["text"] = seq["text"]
        _save_alert(db, analysis, "upload", current_user)
        results.append(analysis)

    return {
        "total_sequences": len(sequences),
        "anomalies_found": sum(1 for r in results if r["is_anomaly"]),
        "results":         results[:50],
    }


# ── Get alerts — FIXED: always returns list ───────────────────────────────────
@router.get("/alerts")
def get_alerts(
    skip:         int = 0,
    limit:        int = 50,
    severity:     str = None,
    search:       str = None,
    source:       str = None,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if source:
        query = query.filter(Alert.source == source)
    if search:
        query = query.filter(Alert.log_text.contains(search))

    total  = query.count()
    alerts = query.order_by(Alert.timestamp.desc()).offset(skip).limit(limit).all()

    # Always returns a plain list — frontend reads this directly
    return [
        {
            "id":             a.id,
            "timestamp":      a.timestamp.isoformat(),
            "log_text":       a.log_text,
            "severity":       a.severity,
            "severity_score": a.severity_score,
            "ip_addresses":   a.ip_addresses,
            "usernames":      a.usernames,
            "ml_confidence":  a.ml_confidence,
            "source":         a.source,
            "explanation":    json.loads(a.explanation) if a.explanation else [],
        }
        for a in alerts
    ]


# ── Stats ─────────────────────────────────────────────────────────────────────
@router.get("/stats")
def get_stats(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    return {
        "total":  db.query(Alert).count(),
        "high":   db.query(Alert).filter(Alert.severity == "HIGH").count(),
        "medium": db.query(Alert).filter(Alert.severity == "MEDIUM").count(),
        "low":    db.query(Alert).filter(Alert.severity == "LOW").count(),
    }


# ── Export CSV ────────────────────────────────────────────────────────────────
@router.get("/alerts/export/csv")
def export_csv(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(500).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Timestamp","Severity","Score","IPs","Log Text","Source"])
    for a in alerts:
        writer.writerow([
            a.id, a.timestamp, a.severity,
            round(a.severity_score or 0, 3),
            a.ip_addresses or "",
            (a.log_text or "")[:200],
            a.source or "",
        ])
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition":"attachment; filename=alerts.csv"},
    )


# ── Export PDF ────────────────────────────────────────────────────────────────
@router.get("/alerts/export/pdf")
def export_pdf(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(100).all()
    buf    = io.BytesIO()
    c      = rl_canvas.Canvas(buf, pagesize=A4)
    w, h   = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, h-50, "CyberAI Monitor — Threat Report")
    c.setFont("Helvetica", 10)
    c.drawString(40, h-70, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    c.drawString(40, h-85, f"Total alerts: {len(alerts)}")

    y = h - 120
    c.setFont("Helvetica-Bold", 9)
    c.drawString(40,  y, "Time")
    c.drawString(160, y, "Severity")
    c.drawString(240, y, "Score")
    c.drawString(300, y, "IPs")
    c.drawString(420, y, "Log Preview")
    y -= 15

    c.setFont("Helvetica", 8)
    for a in alerts:
        if y < 60:
            c.showPage(); y = h-60; c.setFont("Helvetica", 8)
        c.drawString(40,  y, str(a.timestamp)[:16])
        c.drawString(160, y, a.severity or "")
        c.drawString(240, y, str(round(a.severity_score or 0, 2)))
        c.drawString(300, y, (a.ip_addresses or "")[:18])
        c.drawString(420, y, (a.log_text or "")[:40])
        y -= 13

    c.save()
    buf.seek(0)
    return StreamingResponse(
        buf, media_type="application/pdf",
        headers={"Content-Disposition":"attachment; filename=threat_report.pdf"},
    )


# ── Model stats ───────────────────────────────────────────────────────────────
@router.get("/model/stats")
def model_stats(current_user: User = Depends(get_current_user)):
    texts, labels = get_training_data()
    total = len(texts)
    return {
        "total_training_samples": total,
        "anomaly_samples":        labels.count(1),
        "normal_samples":         labels.count(0),
        "anomaly_ratio":          round(labels.count(1)/total, 3),
        "model_type":             "SVM + RandomForest Ensemble",
        "status":                 "trained",
    }


# ── Retrain ───────────────────────────────────────────────────────────────────
@router.post("/model/retrain")
def retrain_model(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    engine._train()
    texts, labels = get_training_data()
    return {"message":"Model retrained successfully", "samples":len(texts)}


# ── AI Chat ───────────────────────────────────────────────────────────────────
class ChatPayload(BaseModel):
    message: str
    history: list = []

try:
    import httpx

    @router.post("/chat")
    async def ai_chat(
        payload:      ChatPayload,
        current_user: User    = Depends(get_current_user),
        db:           Session = Depends(get_db),
    ):
        import os
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise HTTPException(status_code=500, detail="AI chat not configured on server")

        alerts  = db.query(Alert).order_by(Alert.timestamp.desc()).limit(5).all()
        context = "\n".join([
            f"{a.severity} — IP:{a.ip_addresses or 'none'} — {(a.log_text or '')[:80]}"
            for a in alerts
        ])

        messages = [
            *[{"role":m["role"],"content":m["text"]} for m in payload.history[-10:]],
            {"role":"user","content":payload.message},
        ]

        async with httpx.AsyncClient() as client:
            res = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":         api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type":      "application/json",
                },
                json={
                    "model":      "claude-sonnet-4-20250514",
                    "max_tokens": 600,
                    "system":     f"You are a cybersecurity expert.\nRecent alerts:\n{context}",
                    "messages":   messages,
                },
                timeout=30.0,
            )
        data = res.json()
        if "error" in data:
            raise HTTPException(status_code=400, detail=data["error"]["message"])
        return {"reply": data["content"][0]["text"]}

except ImportError:
    pass


# ── Get / update notification preferences ────────────────────────────────────
class NotifPrefs(BaseModel):
    notify_email:        bool   = False
    notify_sms:          bool   = False
    notify_phone:        str    = ""
    notify_min_severity: str    = "HIGH"

@router.get("/notifications/prefs")
def get_notif_prefs(current_user: User = Depends(get_current_user)):
    return {
        "notify_email":        current_user.notify_email,
        "notify_sms":          current_user.notify_sms,
        "notify_phone":        current_user.notify_phone or "",
        "notify_min_severity": current_user.notify_min_severity or "HIGH",
    }

@router.put("/notifications/prefs")
def update_notif_prefs(
    prefs:        NotifPrefs,
    current_user: User    = Depends(get_current_user),
    db:           Session = Depends(get_db),
):
    current_user.notify_email        = prefs.notify_email
    current_user.notify_sms          = prefs.notify_sms
    current_user.notify_phone        = prefs.notify_phone or None
    current_user.notify_min_severity = prefs.notify_min_severity
    db.commit()
    return {"message": "Notification preferences saved"}