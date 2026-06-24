from typing import Dict, Any
from src.schema import State, Threat
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel
from typing import List

import logging
logger = logging.getLogger(__name__)


class DetectionResult(BaseModel):
    threats: List[Threat]

def detect_node(state: State) -> Dict[str, Any]:
    """Identifies brute force patterns or anomalies from the cleaned logs."""
    clean_logs = state.get("clean_logs", [])
    
    if not clean_logs:
        return {"threats": []}

    # Format logs for the LLM including arbitrary kwargs like cmdline
    logs_str = "\n".join([f"{log.timestamp} | {log.ip} | {log.event} | {log.kwargs}" for log in clean_logs])

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a Cyber Threat Hunter. Analyze the following security logs and detect any threats such as brute-force attacks or suspicious behaviors. Output a list of identified threats with confidence scores. Return an empty list if there are no threats."),
        ("user", "Logs:\n{logs}")
    ])
    
    import os
    if not os.getenv("OPENAI_API_KEY"):
        logger.info("OPENAI_API_KEY not found. Using fallback heuristic for detection.")
        threats = _heuristic_detection(clean_logs)
        return {"threats": threats}

    # Initialize the LLM (Requires OPENAI_API_KEY environment variable)
    # Using a relatively low temperature for analytical task
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    structured_llm = llm.with_structured_output(DetectionResult)
    
    chain = prompt | structured_llm
    
    try:
        result = chain.invoke({"logs": logs_str})
        threats = result.threats
    except Exception as e:
        logger.info(f"Error during detection (using fallback heuristic): {e}")
        # Fallback heuristic for demonstration if LLM fails (e.g. no API key)
        threats = _heuristic_detection(clean_logs)
        
    return {"threats": threats}

def _heuristic_detection(logs) -> List[Threat]:
    """A simple programmatic fallback if LLM is unavailable."""
    failed_logins = [log for log in logs if log.event == "failed_login"]
    if len(failed_logins) > 3:
        return [Threat(threat="Brute Force Attack", confidence=0.95, details=f"Detected {len(failed_logins)} failed logins from IP {failed_logins[0].ip}.")]
    return []
