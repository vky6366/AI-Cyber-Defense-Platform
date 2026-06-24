from typing import Dict, Any
from src.schema import State, LogEntry

import logging
logger = logging.getLogger(__name__)


def ingest_node(state: State) -> Dict[str, Any]:
    """Parses, validates, and normalizes the input security logs."""
    raw_logs = state.get("raw_logs", [])
    clean_logs = []
    
    for log in raw_logs:
        try:
            # Basic validation using Pydantic
            entry = LogEntry(**log)
            clean_logs.append(entry)
        except Exception as e:
            # In a real system, we might log the error and continue or send to dead-letter queue
            logger.info(f"Failed to parse log entry: {log}. Error: {e}")
            
    return {"clean_logs": clean_logs}
