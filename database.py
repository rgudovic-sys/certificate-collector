from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
import re

DATABASE_URL = os.getenv("DATABASE_URL")

engine = None
SessionLocal = None

if DATABASE_URL:
    try:
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        
        match = re.match(r'^(postgresql://)([^:]+):(.+)@(.+)$', DATABASE_URL)
        if match:
            scheme, user, password, rest = match.groups()
            import urllib.parse
            encoded_password = urllib.parse.quote(password, safe='')
            clean_url = f"{scheme}{user}:{encoded_password}@{rest}"
        else:
            clean_url = DATABASE_URL
        
        if "?" in clean_url:
            base_url = clean_url.split("?")[0]
        else:
            base_url = clean_url
        
        engine = create_engine(
            base_url,
            connect_args={"sslmode": "require", "connect_timeout": 10},
            pool_pre_ping=True,
            pool_timeout=5
        )
        
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    except Exception as e:
        print(f"Database connection error: {type(e).__name__}: {e}")
        engine = None
        SessionLocal = None

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
    if not SessionLocal:
        yield None
        return
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        print(f"DB session error: {type(e).__name__}: {e}")
        yield None
    finally:
        try:
            db.close()
        except Exception:
            pass

def init_db():
    if engine:
        Base.metadata.create_all(bind=engine)
