from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import ssl
import socket
from datetime import datetime
from cryptography import x509
from typing import List, Optional
from sqlalchemy.orm import Session
from database import get_db, init_db, CertificateScan

app = FastAPI(title="Certificate Collector")

@app.on_event("startup")
def startup():
    init_db()

class HostnameRequest(BaseModel):
    hostnames: List[str]
    port: int = 443

class CertificateInfo(BaseModel):
    hostname: str
    port: int
    subject: dict
    issuer: dict
    serial_number: str
    not_before: str
    not_after: str
    san: List[str]
    key_info: dict
    error: Optional[str] = None

class ScanResponse(BaseModel):
    id: int
    hostname: str
    port: int
    subject: dict
    issuer: dict
    serial_number: str
    not_before: str
    not_after: str
    san: List[str]
    key_info: dict
    error: Optional[str] = None
    scanned_at: datetime

def parse_name(name) -> dict:
    result = {}
    for attr in name:
        result[attr.oid._name] = str(attr.value)
    return result

def collect_certificate(hostname: str, port: int = 443) -> CertificateInfo:
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der)
                
                san_list = []
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san_list = san_ext.value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    pass
                
                key_info = {}
                if cert.public_key():
                    pub_key = cert.public_key()
                    key_info["algorithm"] = pub_key.__class__.__name__
                    if hasattr(pub_key, 'key_size'):
                        key_info["size"] = pub_key.key_size
                
                return CertificateInfo(
                    hostname=hostname,
                    port=port,
                    subject=parse_name(cert.subject),
                    issuer=parse_name(cert.issuer),
                    serial_number=str(cert.serial_number),
                    not_before=cert.not_valid_before.isoformat(),
                    not_after=cert.not_valid_after.isoformat(),
                    san=san_list,
                    key_info=key_info
                )
                
    except Exception as e:
        return CertificateInfo(
            hostname=hostname,
            port=port,
            subject={},
            issuer={},
            serial_number="",
            not_before="",
            not_after="",
            san=[],
            key_info={},
            error=str(e)
        )

@app.post("/api/certificates")
def get_certificates(request: HostnameRequest, db: Session = Depends(get_db)):
    results = []
    for hostname in request.hostnames:
        hostname = hostname.strip()
        if hostname:
            cert_info = collect_certificate(hostname, request.port)
            
            if db:
                db_scan = CertificateScan(
                    hostname=cert_info.hostname,
                    port=cert_info.port,
                    subject=cert_info.subject,
                    issuer=cert_info.issuer,
                    serial_number=cert_info.serial_number,
                    not_before=cert_info.not_before,
                    not_after=cert_info.not_after,
                    san=cert_info.san,
                    key_info=cert_info.key_info,
                    error=cert_info.error
                )
                db.add(db_scan)
                db.commit()
                db.refresh(db_scan)
                
                results.append(ScanResponse(
                    id=db_scan.id,
                    hostname=db_scan.hostname,
                    port=db_scan.port,
                    subject=db_scan.subject,
                    issuer=db_scan.issuer,
                    serial_number=db_scan.serial_number,
                    not_before=db_scan.not_before,
                    not_after=db_scan.not_after,
                    san=db_scan.san,
                    key_info=db_scan.key_info,
                    error=db_scan.error,
                    scanned_at=db_scan.scanned_at
                ))
            else:
                results.append(CertificateInfo(
                    hostname=cert_info.hostname,
                    port=cert_info.port,
                    subject=cert_info.subject,
                    issuer=cert_info.issuer,
                    serial_number=cert_info.serial_number,
                    not_before=cert_info.not_before,
                    not_after=cert_info.not_after,
                    san=cert_info.san,
                    key_info=cert_info.key_info,
                    error=cert_info.error
                ))
    
    return {"certificates": results}

@app.get("/api/history")
def get_history(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    if not db:
        return {"scans": []}
    scans = db.query(CertificateScan).order_by(CertificateScan.scanned_at.desc()).offset(skip).limit(limit).all()
    return {"scans": [
        ScanResponse(
            id=s.id,
            hostname=s.hostname,
            port=s.port,
            subject=s.subject,
            issuer=s.issuer,
            serial_number=s.serial_number,
            not_before=s.not_before,
            not_after=s.not_after,
            san=s.san,
            key_info=s.key_info,
            error=s.error,
            scanned_at=s.scanned_at
        ) for s in scans
    ]}

@app.delete("/api/history/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    if not db:
        return {"status": "no database"}
    db.query(CertificateScan).filter(CertificateScan.id == scan_id).delete()
    db.commit()
    return {"status": "deleted"}

@app.get("/", response_class=HTMLResponse)
def get_ui():
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())


