from typing import Dict, Any
from src.schema import State

import logging
logger = logging.getLogger(__name__)


def approval_node(state: State) -> Dict[str, Any]:
    """Human-in-the-Loop gate for remediation actions."""
    # If state is already injected via API resume, return it
    if "approved" in state and "analyst_notes" in state:
        return {
            "approved": state["approved"],
            "analyst_notes": state["analyst_notes"]
        }

    severity = state.get("severity", "Low")
    
    # If severity is Low, we don't require approval
    if severity == "Low":
        return {"approved": True, "analyst_notes": "Auto-approved for Low severity."}
        
    threats = state.get("enriched_threats") or state.get("threats", [])
    if not threats:
        return {"approved": True, "analyst_notes": "No threats detected."}
        
    threat_names = ", ".join([t.threat for t in threats])
    actions = state.get("response_actions", [])
    
    logger.info(f"\nThreat:\n{threat_names}")
    logger.info(f"\nSeverity:\n{severity.upper()}")
    logger.info("\nRecommended Actions:\n")
    for i, action in enumerate(actions, 1):
        logger.info(f"{i}. {action}")
        
    logger.info()
    
    import sys
    if not sys.stdin.isatty():
        # Running in a non-interactive environment (like API without interrupt state)
        # Should not happen if correctly configured with interrupts
        logger.info("Non-interactive environment detected. Auto-approving.")
        return {"approved": True, "analyst_notes": "Auto-approved due to non-interactive environment."}

    while True:
        try:
            approval = input("Approve actions? (y/n): ").strip().lower()
            if approval in ['y', 'n']:
                break
            logger.info("Please enter 'y' or 'n'.")
        except EOFError:
            approval = 'y'
            break
        
    approved = (approval == 'y')
    try:
        notes = input("\nAnalyst Notes (optional): ").strip()
    except EOFError:
        notes = ""
    
    return {
        "approved": approved,
        "analyst_notes": notes
    }
