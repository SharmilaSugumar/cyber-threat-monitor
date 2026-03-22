from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()  # load .env file

from .routes import auth, analysis
from .database import init_db

# ── Create app FIRST ──────────────────────────────────────────────────────────
app = FastAPI(
    title="CyberAI Threat Monitor API",
    version="2.0.0",
    description="AI-powered log intelligence platform with JWT auth",
)

# ── CORS middleware ───────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://cyber-threat-monitor.vercel.app",
        "https://cyber-threat-monitor-git-main-sharmilas-projects-6b1cb0dd.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ── Include routers AFTER app is created ─────────────────────────────────────
app.include_router(auth.router,     prefix="/api/auth", tags=["auth"])
app.include_router(analysis.router, prefix="/api",      tags=["analysis"])

# ── Try to include websocket router (optional) ────────────────────────────────
try:
    from .routes import websocket as ws_router
    app.include_router(ws_router.router, tags=["websocket"])
    print("✅ WebSocket router loaded")
except ImportError:
    print("⚠️  WebSocket router not found — skipping")


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    init_db()
    print("🚀 CyberAI API started — docs at http://localhost:8000/docs")


@app.get("/")
def root():
    return {"status": "running", "version": "2.0.0"}


@app.get("/ping")
def ping():
    return {"status": "alive"}
