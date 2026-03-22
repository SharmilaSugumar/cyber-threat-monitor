from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    log_text = Column(Text)
    severity = Column(String(10))   # LOW / MEDIUM / HIGH
    severity_score = Column(Float)
    is_anomaly = Column(Integer)    # 0 or 1
    explanation = Column(Text)      # Why was this flagged?
    ip_addresses = Column(String(200))
    usernames = Column(String(200))