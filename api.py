import os
import uuid
import logging
from typing import List, Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from src.database import get_db, Base, engine
from src.models import Incident, AuditLog, ThreatIntelligence
from src.graph import build_graph

# Try to use LangGraph's Postgres checkpointer, fallback to memory if error
try:
    from langgraph.checkpoint.postgres import PostgresSaver
    from psycopg_pool import ConnectionPool
    import psycopg
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:Kalyan@localhost:5432/cyberdefense")
    
    # Run setup with autocommit=True to avoid transaction errors
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        PostgresSaver(conn).setup()
        
    pool = ConnectionPool(conninfo=DATABASE_URL)
    checkpointer = PostgresSaver(pool)
    USING_POSTGRES_CHECKPOINTER = True
except Exception as e:
    logger.warning(f"Failed to setup PostgresSaver ({e}). Falling back to MemorySaver.")
    from langgraph.checkpoint.memory import MemorySaver
    checkpointer = MemorySaver()
    USING_POSTGRES_CHECKPOINTER = False

# Initialize Database
Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI Cyber Defense Platform API", version="1.0.0")

workflow = build_graph()
# Compile with checkpointer and interrupt before approval
graph_app = workflow.compile(checkpointer=checkpointer, interrupt_before=["approval"])

class AnalyzeRequest(BaseModel):
    logs: List[Dict[str, Any]]

class ApproveRequest(BaseModel):
    approved: bool
    notes: Optional[str] = ""

@app.get("/health", summary="Health Check", description="Returns the health status of the API")
def health_check():
    return {"status": "healthy"}

@app.post(
    "/analyze",
    summary="Analyze security logs",
    description="Accepts a list of raw security logs, processes them using the AI LangGraph agents, and creates a new incident if a threat is detected."
)
async def analyze_logs(request: AnalyzeRequest, db: Session = Depends(get_db)):
    incident_id = str(uuid.uuid4())
    
    # Start graph execution
    config = {"configurable": {"thread_id": incident_id}}
    initial_state = {
        "incident_id": incident_id,
        "raw_logs": request.logs
    }
    
    # Run the graph asynchronously
    try:
        final_state = await graph_app.ainvoke(initial_state, config=config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Graph execution failed: {e}")
        
    # Check if incident was created in DB
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        severity = final_state.get("severity", "Unknown")
        return {"incident_id": incident_id, "severity": severity, "status": "completed", "message": "No incident recorded or auto-resolved."}
        
    return {
        "incident_id": incident.incident_id,
        "severity": incident.severity,
        "status": incident.status
    }

@app.get(
    "/incidents",
    summary="Get all incidents",
    description="Retrieve a list of all security incidents recorded in the database."
)
def get_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    return incidents

@app.get(
    "/incidents/{incident_id}",
    summary="Get incident details",
    description="Retrieve detailed information about a specific incident by its ID."
)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@app.post(
    "/incidents/{incident_id}/approve",
    summary="Approve or Reject an incident",
    description="Human-in-the-loop approval gate. Determines if an incident response should be executed or rejected."
)
async def approve_incident(incident_id: str, request: ApproveRequest, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    if incident.status != "pending_approval":
        raise HTTPException(status_code=400, detail=f"Incident is in {incident.status} state, cannot approve.")
        
    # Update DB
    incident.approved = request.approved
    incident.analyst_notes = request.notes
    incident.status = "approved" if request.approved else "rejected"
    
    # Audit log
    audit = AuditLog(
        action=f"Incident {incident.status}",
        notes=request.notes
    )
    db.add(audit)
    db.commit()
    
    # Resume Graph
    config = {"configurable": {"thread_id": incident_id}}
    state_update = {"approved": request.approved, "analyst_notes": request.notes}
    try:
        # Update the state to inject the manual input
        graph_app.update_state(config, state_update, as_node="response")
        # Continue execution
        final_state = await graph_app.ainvoke(None, config=config)
    except Exception as e:
        logging.error(f"Error resuming graph: {e}")
        raise HTTPException(status_code=500, detail=f"Graph resume failed: {e}")
        
    return {"status": incident.status, "message": "Incident updated and report generated."}
    
@app.post("/incidents/{incident_id}/reject")
async def reject_incident(incident_id: str, request: ApproveRequest, db: Session = Depends(get_db)):
    request.approved = False
    return await approve_incident(incident_id, request, db)

from sqlalchemy import func

@app.get(
    "/intel/{incident_id}",
    summary="Get threat intelligence for incident",
    description="Retrieve any gathered threat intelligence data associated with a specific incident."
)
def get_intel(incident_id: str, db: Session = Depends(get_db)):
    intel = db.query(ThreatIntelligence).filter(ThreatIntelligence.incident_id == incident_id).all()
    return intel

@app.get(
    "/intel/top-threats",
    summary="Get top threat IPs",
    description="Aggregate threat intelligence to list the top malicious IP addresses seen across incidents."
)
def get_top_threats(db: Session = Depends(get_db)):
    # Group by IP and count
    top_ips = db.query(
        ThreatIntelligence.ip_address,
        func.count(ThreatIntelligence.id).label('count')
    ).group_by(ThreatIntelligence.ip_address).order_by(func.count(ThreatIntelligence.id).desc()).limit(10).all()
    
    return [{"ip": ip, "count": count} for ip, count in top_ips]

class IPRequest(BaseModel):
    ip: str

@app.post(
    "/intel/ip",
    summary="Check IP reputation",
    description="Check the reputation of a specific IP address using AbuseIPDB."
)
def check_ip(request: IPRequest):
    import requests
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not configured"}
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": request.ip, "maxAgeInDays": 90}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
