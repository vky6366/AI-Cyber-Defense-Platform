from typing import Dict, Any
import re
from src.schema import State

import logging
logger = logging.getLogger(__name__)


def classify_node(state: State) -> Dict[str, Any]:
    """Evaluates the threats and assigns a severity using weighted risk scoring."""
    threats = state.get("enriched_threats") or state.get("threats", [])
    
    if not threats:
        return {"severity": "Low", "risk_score": 0}
        
    history = state.get("historical_incidents", [])
    
    max_risk_score = 0
    
    for t in threats:
        # Base score from LLM confidence (0 to 40)
        risk_score = int(getattr(t, "confidence", 0.5) * 40)
        
        # 1. Malicious IP (+30)
        abuse_score = getattr(t, "abuse_confidence_score", 0) or 0
        if abuse_score > 90 or getattr(t, "ip_reputation", "") == "malicious":
            risk_score += 30
            
        # 2. Previous Incidents (+20)
        # Check if the IP was in historical incidents, or if memory note is in details
        if "MEMORY: This IP has appeared" in t.details:
            risk_score += 20
        else:
            # Try to match IP
            ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', t.details)
            if ip_match:
                ip = ip_match.group()
                if any(h.get("ip") == ip for h in history):
                    risk_score += 20

        # 3. Credential Access (+15)
        tactic = getattr(t, "mitre_tactic", "")
        if tactic == "Credential Access":
            risk_score += 15
            
        # 4. Critical CVE (+35)
        cve = getattr(t, "cve", None)
        if cve and cve != "Unknown":
            # For simplicity, if they have a CVE we assume it's critical or we can check if it has a high CVSS.
            # We don't have severity stored directly on the EnrichedThreat schema unless we parse it.
            # Let's add 35 if CVE is found.
            risk_score += 35
            
        if risk_score > max_risk_score:
            max_risk_score = risk_score
            
    # Cap at 100
    max_risk_score = min(max_risk_score, 100)
    
    # Determine severity
    if max_risk_score <= 30:
        severity = "Low"
    elif max_risk_score <= 60:
        severity = "Medium"
    elif max_risk_score <= 85:
        severity = "High"
    else:
        severity = "Critical"
        
    return {"severity": severity, "risk_score": max_risk_score}
