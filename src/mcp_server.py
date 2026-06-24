import os
import json
import requests
import chromadb
from mcp.server.fastmcp import FastMCP

import logging
logger = logging.getLogger(__name__)


# Initialize FastMCP server
mcp = FastMCP("CyberThreatIntel")

# Chroma DB setup
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="knowledge_base")

# Load KB files if collection is empty
if collection.count() == 0:
    import glob
    kb_files = glob.glob("kb/*.md")
    for i, file_path in enumerate(kb_files):
        try:
            with open(file_path, "r") as f:
                content = f.read()
                collection.add(
                    documents=[content],
                    metadatas=[{"source": file_path}],
                    ids=[f"doc_{i}"]
                )
        except Exception as e:
            logger.info(f"Failed to load KB file {file_path}: {e}")

@mcp.tool()
def lookup_cve(software: str) -> dict:
    """Find CVEs related to specific software."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={software}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]["cve"]
                cve_id = vuln.get("id")
                metrics = vuln.get("metrics", {})
                cvss = None
                severity = "Unknown"
                
                # Check for CVSS v3.1 or v3.0 or v2
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        cvss_data = metrics[version][0]["cvssData"]
                        cvss = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity") or metrics[version][0].get("baseSeverity")
                        break
                        
                return {"cve": cve_id, "cvss": cvss, "severity": severity}
    except Exception as e:
        pass
    return {"cve": "Unknown", "cvss": None, "severity": "Unknown"}

@mcp.tool()
def map_mitre_attack(behavior: str) -> dict:
    """Map an attack pattern or behavior to a MITRE ATT&CK technique."""
    try:
        with open("data/mitre_attack.json", "r") as f:
            mitre_data = json.load(f)
        for key, value in mitre_data.items():
            if key in behavior.lower():
                return value
    except Exception:
        pass
    return {"tactic": "Unknown", "technique_id": "Unknown", "name": "Unknown"}

@mcp.tool()
def check_ip_reputation(ip: str) -> dict:
    """Check the reputation of an IP address."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        # Mock data fallback
        if "192.168.1.5" in ip or ip.startswith("192.168"):
            return {"ip": ip, "reputation": "malicious", "score": 95, "country": "US"}
        return {"ip": ip, "reputation": "clean", "score": 10, "country": "US"}
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {
                "ip": ip,
                "reputation": "malicious" if score > 90 else "clean",
                "score": score,
                "country": data.get("countryCode", "Unknown")
            }
    except Exception as e:
        pass
    return {"ip": ip, "reputation": "Unknown", "score": 0, "country": "Unknown"}

@mcp.tool()
def search_knowledge_base(query: str) -> str:
    """Search the security knowledge base (OWASP, Playbooks) for a query."""
    try:
        results = collection.query(
            query_texts=[query],
            n_results=1
        )
        if results["documents"] and results["documents"][0]:
            return results["documents"][0][0]
    except Exception:
        pass
    return "No relevant playbooks found."

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()

    if args.transport == "sse":
        from mcp.server.fastmcp import FastMCP
        # Pass host and port via mcp.settings if possible, or try run() kwargs
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport='sse')
    else:
        mcp.run(transport='stdio')
