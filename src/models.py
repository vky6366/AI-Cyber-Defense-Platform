from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
import datetime
import uuid

from src.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class Incident(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True, index=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    severity = Column(String, index=True)
    threat_type = Column(String)
    status = Column(String, default="pending_approval")
    approved = Column(Boolean, default=False)
    analyst_notes = Column(Text, nullable=True)

    threat_intel = relationship("ThreatIntelligence", back_populates="incident", cascade="all, delete")

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"))
    ip_address = Column(String, index=True)
    reputation = Column(String)
    abuse_confidence_score = Column(Integer, nullable=True)
    country = Column(String, nullable=True)
    risk_score = Column(Integer, nullable=True)
    mitre_tactic = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    cve = Column(String, nullable=True)

    incident = relationship("Incident", back_populates="threat_intel")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String, index=True)
    user = Column(String, default="system")
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    notes = Column(Text, nullable=True)
