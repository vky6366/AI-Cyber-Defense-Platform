from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from src.schema import State
from src.agents.ingest import ingest_node
from src.agents.detect import detect_node
from src.agents.threat_intel import threat_intel_node
from src.agents.classify import classify_node
from src.agents.report import report_node

from src.agents.response import response_node
from src.agents.approval import approval_node

def route_after_response(state: State) -> str:
    severity = state.get("severity", "Low")
    if severity in ["Medium", "High", "Critical"]:
        return "approval"
    return "report"

def route_after_approval(state: State) -> str:
    if state.get("approved", False):
        return "report"
    return END

def build_graph():
    # 1. Initialize StateGraph with our State schema
    workflow = StateGraph(State)
    
    # 2. Add nodes for each agent
    workflow.add_node("ingest", ingest_node)
    workflow.add_node("detect", detect_node)
    workflow.add_node("threat_intel", threat_intel_node)
    workflow.add_node("classify", classify_node)
    workflow.add_node("response", response_node)
    workflow.add_node("approval", approval_node)
    workflow.add_node("report", report_node)
    
    # 3. Define edges connecting the agents in sequence
    workflow.add_edge(START, "ingest")
    workflow.add_edge("ingest", "detect")
    workflow.add_edge("detect", "threat_intel")
    workflow.add_edge("threat_intel", "classify")
    workflow.add_edge("classify", "response")
    
    workflow.add_conditional_edges("response", route_after_response, {
        "approval": "approval",
        "report": "report"
    })
    
    workflow.add_conditional_edges("approval", route_after_approval, {
        "report": "report",
        END: END
    })
    
    workflow.add_edge("report", END)
    
    # 4. Compile the graph
    # We will pass checkpointer at runtime in the API, or use a default one.
    # To support FastAPI, we can just return the workflow and let api.py compile it with the Postgres pool.
    return workflow
