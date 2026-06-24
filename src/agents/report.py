from typing import Dict, Any
from src.schema import State
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate

import logging
logger = logging.getLogger(__name__)


def report_node(state: State) -> Dict[str, Any]:
    """Compiles the threats and severity into a professional Markdown Incident Report."""
    logger.info("--- Completed Node: report ---")
    threats = state.get("enriched_threats") or state.get("threats", [])
    severity = state.get("severity", "Unknown")
    
    if not threats:
        return {"report_markdown": "No threats detected. System operating normally."}
        
    approval_info_str = ""
    if "approved" in state:
        approved_str = "Yes" if state["approved"] else "No"
        notes = state.get("analyst_notes", "None")
        approval_info_str = f"## Human Approval\nApproved: {approved_str}\n\nAnalyst Notes:\n{notes}\n"

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are an Incident Response Report Agent. Generate a concise, professional Markdown incident report based on the provided threats and severity. Include sections for Threat, Severity, Affected Assets, MITRE ATT&CK mapping, Recommended Actions, and Confidence. If 'Approval Info' is provided, include it in a 'Human Approval' section exactly as provided."),
        ("user", "Severity: {severity}\nThreats:\n{threats}\nApproval Info:\n{approval_info}")
    ])
    
    threats_str_list = []
    for t in threats:
        t_str = f"- {t.threat} (Confidence: {t.confidence}): {t.details}"
        if getattr(t, "mitre_tactic", None):
            t_str += f"\n  - MITRE: {t.mitre_tactic} ({t.mitre_technique_id})"
        if getattr(t, "ip_reputation", None):
            t_str += f"\n  - IP Reputation: {t.ip_reputation}"
        if getattr(t, "playbook_recommendation", None):
            t_str += f"\n  - Playbook: {t.playbook_recommendation}"
        if getattr(t, "cve", None):
            t_str += f"\n  - CVE: {t.cve}"
        threats_str_list.append(t_str)
        
    threats_str = "\n".join(threats_str_list)

    import os
    if not os.getenv("OPENAI_API_KEY"):
        logger.info("OPENAI_API_KEY not found. Using fallback heuristic for reporting.")
        report = f"""# Incident Report

**Severity:** {severity}

## Threats Detected (Enriched):
{threats_str}

## Recommended Actions:
- Review the matched playbooks and MITRE techniques above.
- Block any malicious IP addresses immediately.

{approval_info_str}
*Note: Report generated via fallback due to LLM error or missing API key.*"""
        return {"report_markdown": report}

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.2)
    chain = prompt | llm

    try:
        result = chain.invoke({"severity": severity, "threats": threats_str, "approval_info": approval_info_str})
        report = result.content
    except Exception as e:
        logger.info(f"Error during report generation (using fallback heuristic): {e}")
        # Fallback
        report = f"""# Incident Report

**Severity:** {severity}

## Threats Detected:
{threats_str}

## Recommended Actions:
- Review the matched playbooks and MITRE techniques above.
- Block any malicious IP addresses immediately.

{approval_info_str}
*Note: Report generated via fallback due to LLM error or missing API key.*"""
        
    return {"report_markdown": report}
