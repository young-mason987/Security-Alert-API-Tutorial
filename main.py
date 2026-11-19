import os
import secrets

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import Literal

app = FastAPI(title="Security Alert API")

api_key_header = APIKeyHeader(name="X-API-Key")

def verify_api_key(key: str = Depends(api_key_header)):
    expected_key = os.getenv("SECURITY_API_KEY")

    if key != expected_key:
        raise HTTPException(status_code=500, detail="Server authentication is not configured properly.")
    
    if not secrets.compare_digest(key, expected_key):
        raise HTTPException(status_code=403, detail="Invalid API Key")

    return key

    
class AlertInput(BaseModel):
    device: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]

class StatusUpdate(BaseModel):
   status: Literal["open", "in_progress", "resolved"]

alerts = []
next_id = 1

@app.get("/")
def home():
    return {"message": "Security alert API is running!"}

@app.get("/alerts")
def get_alerts():
    return alerts

@app.post("/alerts", status_code=201)
def create_alert(alert: AlertInput,
                 key: str = Depends(verify_api_key)):
    global next_id

    new_alert = {
        "id": next_id,
        "device": alert.device,
        "description": alert.description,
        "severity": alert.severity,
        "status": "open"
    }
    alerts.append(new_alert)
    next_id += 1
    return new_alert

@app.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, update: StatusUpdate,
                 key: str = Depends(verify_api_key)):

    for alert in alerts:
        if alert["id"] == alert_id:
            alert["status"] = update.status
            return alert

    raise HTTPException(status_code=404, detail="Alert not found")
