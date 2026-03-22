from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models.models import Base, User
from .core.security import get_password_hash
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyber_monitor.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables and seed default admin user."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == "admin").first()
        if not existing:
            admin = User(
                username="admin",
                email="admin@cyberai.com",
                full_name="Admin User",
                role="admin",
                hashed_password=get_password_hash("admin123"),
                is_active=True,
            )
            analyst = User(
                username="analyst",
                email="analyst@cyberai.com",
                full_name="SOC Analyst",
                role="analyst",
                hashed_password=get_password_hash("analyst123"),
                is_active=True,
            )
            db.add(admin)
            db.add(analyst)
            db.commit()
            print("✅ Default users created: admin/admin123 and analyst/analyst123")
    finally:
        db.close()