from typing import Dict, Any, List
from src.schema import State
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
import os

import logging
logger = logging.getLogger(__name__)


class ResponseResult(BaseModel):
    actions: List[str] = Field(description="List of recommended remediation actions")

def response_node(state: State) -> Dict[str, Any]:
    """Generates remediation actions based on the threat analysis."""
    threats = state.get("enriched_threats") or state.get("threats", [])
    severity = state.get("severity", "Low")
    
    if not threats or severity == "Low":
        return {"response_actions": []}
        
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a cybersecurity incident response specialist.

Based on:
- Threat Type
- Severity
- MITRE ATT&CK Mapping
- Threat Intelligence

Generate recommended remediation actions.

Prioritize:
1. Immediate containment
2. Eradication
3. Recovery

Return concise action steps."""),
        ("user", "Severity: {severity}\nThreats:\n{threats}")
    ])
    
    if not os.getenv("OPENAI_API_KEY"):
        logger.info("OPENAI_API_KEY not found. Using fallback heuristic for response actions.")
        actions = ["Block IP Address", "Reset Credentials", "Enable MFA"]
        return {"response_actions": actions}

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    structured_llm = llm.with_structured_output(ResponseResult)
    chain = prompt | structured_llm
    
    try:
        threats_str = "\n".join([f"- {t.threat} (Confidence: {t.confidence}): {t.details}" for t in threats])
        result = chain.invoke({"severity": severity, "threats": threats_str})
        actions = result.actions
    except Exception as e:
        logger.info(f"Error during response generation (using fallback heuristic): {e}")
        actions = ["Block IP Address", "Reset Credentials", "Enable MFA"]
        
    # Save to database
    from src.database import get_db
    from src.models import Incident, ThreatIntelligence
    
    incident_id = state.get("incident_id")
    if incident_id:
        db_gen = get_db()
        db = next(db_gen)
        try:
            # Check if incident already exists to avoid duplicate insertions on retry
            existing = db.query(Incident).filter(Incident.incident_id == incident_id).first()
            if not existing:
                incident = Incident(
                    incident_id=incident_id,
                    severity=severity,
                    threat_type=threats[0].threat if threats else "Unknown",
                    status="pending_approval" if severity in ["Medium", "High", "Critical"] else "approved",
                    approved=(severity not in ["Medium", "High", "Critical"])
                )
                db.add(incident)
                db.commit()
                
                clean_logs = state.get("clean_logs", [])
                ip_addr = clean_logs[0].ip if clean_logs else "Unknown"
                
                for t in threats:
                    ti = ThreatIntelligence(
                        incident_id=incident_id,
                        ip_address=ip_addr,
                        reputation=getattr(t, "ip_reputation", "Unknown") or "Unknown",
                        mitre_tactic=getattr(t, "mitre_tactic", None),
                        mitre_technique=getattr(t, "mitre_technique_id", None),
                        cve=getattr(t, "cve", None)
                    )
                    db.add(ti)
                db.commit()
        except Exception as e:
            db.rollback()
            logger.info(f"Failed to save incident to DB: {e}")
        finally:
            db.close()

    return {"response_actions": actions}
