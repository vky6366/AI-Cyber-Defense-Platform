from typing import TypedDict, List, Dict, Any, Optional, Annotated
import operator
from pydantic import BaseModel, Field

class LogEntry(BaseModel):
    timestamp: str
    ip: str
    event: str

class Threat(BaseModel):
    threat: str
    confidence: float
    details: str

class IncidentReport(BaseModel):
    threat_summary: str
    severity: str
    affected_assets: str
    mitre_attack: str
    recommended_actions: List[str]
    confidence: float

class EnrichedThreat(BaseModel):
    threat: str
    confidence: float
    details: str
    cve: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    ip_reputation: Optional[str] = None
    abuse_confidence_score: Optional[int] = None
    country: Optional[str] = None
    playbook_recommendation: Optional[str] = None

class State(TypedDict):
    incident_id: str
    raw_logs: List[Dict[str, Any]]
    clean_logs: List[LogEntry]
    threats: List[Threat]
    enriched_threats: List[EnrichedThreat]
    risk_score: int
    severity: str
    report_markdown: str
    historical_incidents: Annotated[List[Dict[str, str]], operator.add]
    approved: bool
    response_actions: List[str]
    analyst_notes: str
