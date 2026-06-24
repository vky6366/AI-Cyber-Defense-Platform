import os
import json
from dotenv import load_dotenv
from src.graph import build_graph

# Load environment variables (e.g., OPENAI_API_KEY)
load_dotenv()

import asyncio

async def run():
    print("Initializing AI Cyber Defense Platform (Phase 2 - MCP Integrated)...")
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("\n[WARNING]: OPENAI_API_KEY is not set in the environment or .env file.")
        print("The agents will use heuristic fallback logic instead of LLMs.\n")
    else:
        print("\n[INFO]: OPENAI_API_KEY detected. Agents will use LLMs.\n")
    
    # Build graph
    app = build_graph()
    
    # Run 1: Day 1 incidents
    print("\n" + "*" * 50)
    print("RUN 1: Day 1 - Initial Brute Force Attempt")
    print("*" * 50)
    
    test_logs_day1 = [
        {"timestamp": "12:01", "ip": "192.168.1.5", "event": "failed_login"},
        {"timestamp": "12:02", "ip": "192.168.1.5", "event": "failed_login"},
        {"timestamp": "12:03", "ip": "192.168.1.5", "event": "failed_login"},
        {"timestamp": "12:04", "ip": "192.168.1.5", "event": "failed_login"}
    ]
    
    config = {"configurable": {"thread_id": "security_monitor_1"}}
    initial_state_1 = {"raw_logs": test_logs_day1}
    
    async for output in app.astream(initial_state_1, config=config):
        for node_name, state_update in output.items():
            print(f"--- Completed Node: {node_name} ---")
            
    print("\n[INFO]: Day 1 Incident Recorded.")
    
    # Run 2: Day 2 incidents (Same IP)
    print("\n" + "*" * 50)
    print("RUN 2: Day 2 - Repeated Brute Force Attempt (Same IP)")
    print("*" * 50)
    
    test_logs_day2 = [
        {"timestamp": "08:01", "ip": "192.168.1.5", "event": "failed_login"},
        {"timestamp": "08:02", "ip": "192.168.1.5", "event": "failed_login"},
        {"timestamp": "08:03", "ip": "192.168.1.5", "event": "failed_login"},
        {"timestamp": "08:04", "ip": "192.168.1.5", "event": "failed_login"}
    ]
    
    initial_state_2 = {"raw_logs": test_logs_day2}
    final_state_update = {}
    
    async for output in app.astream(initial_state_2, config=config):
        for node_name, state_update in output.items():
            print(f"--- Completed Node: {node_name} ---")
            if "enriched_threats" in state_update:
                print(f"  Enriched {len(state_update['enriched_threats'])} threats.")
                for t in state_update["enriched_threats"]:
                    print(f"    - {t.threat} | {t.details.splitlines()[-1] if 'MEMORY' in t.details else ''}")
            final_state_update.update(state_update)
                
    final_report = final_state_update.get("report_markdown", "No report generated.")
    
    print("\n" + "=" * 50)
    print("FINAL INCIDENT REPORT (DAY 2)")
    print("=" * 50 + "\n")
    print(final_report)

if __name__ == "__main__":
    asyncio.run(run())
