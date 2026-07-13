from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./certificates.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class CertificateScan(Base):
    __tablename__ = "certificate_scans"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True)
    port = Column(Integer, default=443)
    subject = Column(JSON)
    issuer = Column(JSON)
    serial_number = Column(String)
    not_before = Column(String)
    not_after = Column(String)
    san = Column(JSON)
    key_info = Column(JSON)
    error = Column(String, nullable=True)
    scanned_at = Column(DateTime, default=datetime.utcnow)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
