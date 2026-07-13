from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.engine import URL
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.getenv("DATABASE_URL")

engine = None
SessionLocal = None

if DATABASE_URL:
    try:
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        
        at_idx = DATABASE_URL.rfind("@")
        if at_idx > 0:
            scheme_user_pass = DATABASE_URL[:at_idx]
            host_db = DATABASE_URL[at_idx + 1:]
            
            scheme, rest = scheme_user_pass.split("://", 1)
            user, password = rest.split(":", 1)
            
            host_db_clean = host_db.split("?")[0]
            parts = host_db_clean.split("/")
            host_port = parts[0]
            dbname = parts[1] if len(parts) > 1 else "postgres"
            
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)
            else:
                host = host_port
                port = 5432
            
            url = URL.create(
                drivername="postgresql",
                username=user,
                password=password,
                host=host,
                port=port,
                database=dbname
            )
            engine = create_engine(url, connect_args={"sslmode": "require", "connect_timeout": 10}, pool_pre_ping=True, pool_timeout=5)
        else:
            engine = create_engine(DATABASE_URL, connect_args={"sslmode": "require", "connect_timeout": 10}, pool_pre_ping=True, pool_timeout=5)
        
        if engine:
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
    is_wildcard = Column(Integer, default=0)
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
