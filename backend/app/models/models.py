from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id               = Column(Integer, primary_key=True, index=True)
    username         = Column(String(50), unique=True, index=True, nullable=False)
    email            = Column(String(100), unique=True, index=True, nullable=False)
    full_name        = Column(String(100), nullable=True)
    role             = Column(String(20), default="analyst")
    hashed_password  = Column(String(200), nullable=False)
    is_active        = Column(Boolean, default=True)
    created_at       = Column(DateTime, default=datetime.utcnow)
    last_login       = Column(DateTime, nullable=True)

    # ── Notification preferences ───────────────────────────────────────────
    notify_email        = Column(Boolean, default=False)
    notify_sms          = Column(Boolean, default=False)
    notify_phone        = Column(String(20), nullable=True)  # e.g. +919876543210
    notify_min_severity = Column(String(10), default="HIGH") # HIGH / MEDIUM / LOW

    alerts        = relationship("Alert",        back_populates="user")
    login_history = relationship("LoginHistory", back_populates="user")


class Alert(Base):
    __tablename__ = "alerts"

    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=datetime.utcnow)
    log_text       = Column(Text)
    severity       = Column(String(10))
    severity_score = Column(Float, default=0.0)
    is_anomaly     = Column(Integer, default=0)
    explanation    = Column(Text)
    ip_addresses   = Column(String(300))
    usernames      = Column(String(300))
    ml_confidence  = Column(Float, default=0.0)
    rule_score     = Column(Float, default=0.0)
    source         = Column(String(50), default="manual")
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=True)

    user = relationship("User", back_populates="alerts")


class LoginHistory(Base):
    __tablename__ = "login_history"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"))
    timestamp  = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(50))
    user_agent = Column(String(200))
    success    = Column(Boolean, default=True)

    user = relationship("User", back_populates="login_history")