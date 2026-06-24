import json
import re
from typing import Dict, Any
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client
from src.schema import State, EnrichedThreat
import os
import contextlib

import logging
logger = logging.getLogger(__name__)


async def threat_intel_node(state: State) -> Dict[str, Any]:
    """Connects to the MCP server to enrich threats with intel data."""
    threats = state.get("threats", [])
    if not threats:
        return {"enriched_threats": []}

    mcp_url = os.getenv("MCP_SERVER_URL")
    
    @contextlib.asynccontextmanager
    async def get_mcp_client():
        if mcp_url:
            async with sse_client(mcp_url) as (read, write):
                yield read, write
        else:
            server_params = StdioServerParameters(
                command="python",
                args=["src/mcp_server.py"]
            )
            async with stdio_client(server_params) as (read, write):
                yield read, write

    enriched_threats = []
    
    try:
        async with get_mcp_client() as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                for t in threats:
                    enriched = EnrichedThreat(
                        threat=t.threat,
                        confidence=t.confidence,
                        details=t.details
                    )
                    
                    # 1. Map to MITRE ATT&CK
                    try:
                        mitre_res = await session.call_tool("map_mitre_attack", arguments={"behavior": t.threat})
                        if mitre_res.content:
                            mitre_data = json.loads(mitre_res.content[0].text)
                            enriched.mitre_tactic = mitre_data.get("tactic")
                            enriched.mitre_technique_id = mitre_data.get("technique_id")
                    except Exception as e:
                        logger.info(f"MCP MITRE error: {e}")
                        
                    # 2. IP Reputation
                    try:
                        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', t.details)
                        if ip_match:
                            ip = ip_match.group()
                            ip_res = await session.call_tool("check_ip_reputation", arguments={"ip": ip})
                            if ip_res.content:
                                ip_data = json.loads(ip_res.content[0].text)
                                enriched.ip_reputation = ip_data.get("reputation")
                                enriched.abuse_confidence_score = ip_data.get("score")
                                enriched.country = ip_data.get("country")
                    except Exception as e:
                        logger.info(f"MCP IP Reputation error: {e}")
                            
                    # 3. Knowledge Base
                    try:
                        kb_res = await session.call_tool("search_knowledge_base", arguments={"query": t.threat})
                        if kb_res.content:
                            enriched.playbook_recommendation = kb_res.content[0].text
                    except Exception as e:
                        logger.info(f"MCP KB error: {e}")
                        
                    # 4. CVE Lookup (if applicable)
                    try:
                        # Extract software if mentioned, or default to checking common ones
                        software_to_check = None
                        for sw in ["apache", "openssh", "nginx", "windows"]:
                            if sw in t.details.lower() or sw in t.threat.lower():
                                software_to_check = sw
                                break
                                
                        if software_to_check:
                            cve_res = await session.call_tool("lookup_cve", arguments={"software": software_to_check})
                            if cve_res.content:
                                cve_data = json.loads(cve_res.content[0].text)
                                enriched.cve = cve_data.get("cve")
                    except Exception as e:
                        logger.info(f"MCP CVE error: {e}")
                            
                    enriched_threats.append(enriched)
                    
    except Exception as e:
        logger.info(f"Error communicating with MCP Server: {e}")
        # Fallback if MCP server fails
        for t in threats:
            enriched_threats.append(EnrichedThreat(
                threat=t.threat,
                confidence=t.confidence,
                details=t.details,
                mitre_tactic="Unknown",
                mitre_technique_id="Unknown",
                ip_reputation="Unknown",
                playbook_recommendation="Review standard playbooks."
            ))
            
    # Process memory
    history = state.get("historical_incidents", [])
    new_incidents = []
    
    for enriched in enriched_threats:
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', enriched.details)
        if ip_match:
            ip = ip_match.group()
            # Count previous incidents for this IP
            past_count = sum(1 for inc in history if inc.get("ip") == ip)
            
            if past_count > 0:
                memory_note = f"MEMORY: This IP has appeared in {past_count} previous incidents."
                enriched.details += f"\n{memory_note}"
                
            new_incidents.append({"ip": ip, "threat": enriched.threat})

    return {"enriched_threats": enriched_threats, "historical_incidents": new_incidents}
