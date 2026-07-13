from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import ssl
import socket
import json
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from typing import List, Optional

app = FastAPI(title="Certificate Collector")

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
    chain: List[dict]
    error: Optional[str] = None

def parse_name(name) -> dict:
    result = {}
    for attr in name:
        result[attr.oid._name] = str(attr.value)
    return result

def get_certificate_chain(cert_der: bytes) -> List[dict]:
    cert = x509.load_der_x509_certificate(cert_der)
    chain = []
    current_cert = cert
    
    while True:
        chain.append({
            "subject": parse_name(current_cert.subject),
            "issuer": parse_name(current_cert.issuer),
            "serial_number": str(current_cert.serial_number),
            "not_before": current_cert.not_valid_before.isoformat(),
            "not_after": current_cert.not_valid_after.isoformat()
        })
        
        issuer_name = current_cert.issuer
        subject_name = current_cert.subject
        
        if issuer_name == subject_name:
            break
            
        current_cert = x509.load_der_x509_certificate(cert_der)
        break
    
    return chain

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
                
                chain = [{
                    "subject": parse_name(cert.subject),
                    "issuer": parse_name(cert.issuer),
                    "serial_number": str(cert.serial_number),
                    "not_before": cert.not_valid_before.isoformat(),
                    "not_after": cert.not_valid_after.isoformat()
                }]
                
                return CertificateInfo(
                    hostname=hostname,
                    port=port,
                    subject=parse_name(cert.subject),
                    issuer=parse_name(cert.issuer),
                    serial_number=str(cert.serial_number),
                    not_before=cert.not_valid_before.isoformat(),
                    not_after=cert.not_valid_after.isoformat(),
                    san=san_list,
                    key_info=key_info,
                    chain=chain
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
            chain=[],
            error=str(e)
        )

@app.post("/api/certificates")
async def get_certificates(request: HostnameRequest):
    results = []
    for hostname in request.hostnames:
        hostname = hostname.strip()
        if hostname:
            result = collect_certificate(hostname, request.port)
            results.append(result)
    return {"certificates": results}

@app.get("/", response_class=HTMLResponse)
async def get_ui():
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
