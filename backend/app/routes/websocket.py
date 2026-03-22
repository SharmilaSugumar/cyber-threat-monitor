from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..services.detection_engine import HybridDetectionEngine
import asyncio, json, random, datetime

router = APIRouter()
engine = HybridDetectionEngine()


# ── Simulated log lines (Option 3 — demo/presentation mode) ──────────────────
LIVE_LOGS = [
    # Normal operations
    "user admin logged in successfully from 192.168.1.10",
    "user john logged in from 10.0.0.5 session started",
    "file report.pdf accessed by john from 192.168.1.20",
    "scheduled backup completed successfully no errors",
    "user sarah logged out normally session ended",
    "system health check passed all services running",
    "antivirus scan completed no threats found",
    "ssl certificate renewed successfully",
    "dns query resolved for internal.company.com",
    "user mike updated profile no anomaly",

    # Attack patterns
    "failed login attempt for root from 203.0.113.5",
    "failed login attempt for admin from 198.51.100.42",
    "account root locked after multiple failures",
    "port scan detected from 198.51.100.42",
    "unauthorized access attempt to /admin",
    "multiple failed ssh login attempts from 45.33.32.156",
    "privilege escalation attempt detected on server",
    "suspicious outbound connection to 185.220.101.1",
    "malware signature detected in uploaded file",
    "brute force attack detected from 203.0.113.99",
    "sql injection attempt blocked by waf",
    "ransomware behaviour detected on workstation",
    "data exfiltration attempt 500mb to external ip",
    "c2 beacon detected outbound connection",
    "cryptominer process running high cpu usage",
]


# ── Connection manager ────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        print(f"✅ WebSocket client connected — {len(self.active)} total")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
        print(f"WebSocket client disconnected — {len(self.active)} remaining")

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


# ── WebSocket endpoint ────────────────────────────────────────────────────────
@router.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(2)  # send a new log every 2 seconds

            log_line = random.choice(LIVE_LOGS)
            analysis = engine.analyze(log_line)

            await manager.broadcast({
                "type":        "log",
                "timestamp":   datetime.datetime.now().isoformat(),
                "log":         log_line,
                "is_anomaly":  analysis["is_anomaly"],
                "severity":    analysis["severity"]["level"],
                "score":       analysis["severity"]["score"],
                "explanation": analysis["explanation"],
                "entities":    analysis["entities"],
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)