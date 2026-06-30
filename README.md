# AI-Powered SOC Analyst Platform - Architecture Walkthrough

This document provides a detailed, file-by-file walkthrough of the core backend architecture for the AI-Powered SOC Analyst Platform. This system utilizes a multi-agent LangGraph workflow, FastAPI, PostgreSQL, and a Model Context Protocol (MCP) server to dynamically detect, enrich, and respond to cyber threats.

## 1. Core Orchestration

### `api.py`
This is the entry point of the application. It spins up the FastAPI server and acts as the bridge between the HTTP endpoints and the LangGraph workflow.

**Key Responsibilities:**
- **Database & Checkpointer Initialization:** It attempts to initialize `AsyncConnectionPool` and `AsyncPostgresSaver`. This checkpointer is crucial because it allows LangGraph to persist the state of the graph to PostgreSQL. If the database is unreachable, it gracefully falls back to `MemorySaver`.
- **FastAPI Lifespan:** Uses an `@asynccontextmanager` to safely open and close the PostgreSQL async connection pool during the application's startup and shutdown phases.
- **`/analyze` Endpoint:** Takes raw JSON logs from the user, generates a unique `incident_id` (used as the LangGraph `thread_id` for state tracking), and invokes the graph asynchronously (`await graph_app.ainvoke`).
- **`/incidents/{incident_id}/approve` Endpoint:** The "Human-in-the-Loop" gate. It accepts a human analyst's decision (approve/reject), updates the database, and injects the manual decision back into the paused LangGraph state using `graph_app.update_state`. It then resumes the graph execution.
- **`/artifacts/{artifact_value}/incidents` Endpoint:** An IoC correlation endpoint. It allows querying for all incidents involving a specific artifact (e.g., an IP address, username, or domain) across the entire platform.

### `src/graph.py`
This file defines the state machine (Directed Acyclic Graph) for the AI agents using LangGraph.

**Key Responsibilities:**
- **Graph Construction:** Initializes a `StateGraph` using the `State` schema.
- **Node Wiring:** Registers each python function from the `src/agents/` directory as a "node" (e.g., `ingest_node`, `detect_node`).
- **Conditional Routing:** Defines dynamic edges. For example, `route_after_report` checks the `severity` in the state. If it's `Medium`, `High`, or `Critical`, it routes the graph to the `approval` node (pausing for human input). If it's `Low`, it bypasses approval and routes straight to `END`.

### `src/schema.py`
Defines the data structures used throughout the application.

**Key Responsibilities:**
- **LangGraph State:** Defines the `State(TypedDict)` which holds the entire context of a single incident as it moves through the graph (e.g., `raw_logs`, `clean_logs`, `threats`, `severity`, `approved`).
- **Pydantic Models:** Provides strict validation schemas for the LLM to output (e.g., `DetectionResult`, `Threat`). 
- **Dynamic Field Support:** The `LogEntry` model explicitly uses a `kwargs` field to capture arbitrary log metadata (like `cmdline` or `user_agent`) so that the AI doesn't lose context on complex attacks.

---

## 2. Multi-Agent Workflow (`src/agents/`)

The core logic of the platform is divided into specialized nodes. Each node represents a step in the graph, taking the current `State` as input and returning a dictionary of state updates.

### `src/agents/ingest.py`
**Purpose:** Data normalization and parsing.
- Takes the `raw_logs` from the API request.
- Uses Pydantic's `LogEntry` model to validate core fields (`timestamp`, `ip`, `event`).
- Extracts any extra fields (like `cmdline`) and dynamically packs them into the `kwargs` property to ensure no contextual data is lost.

### `src/agents/detect.py`
**Purpose:** AI-driven threat hunting.
- Connects to OpenAI (`gpt-4o-mini`) using Langchain.
- Formats the cleaned logs into a readable string and prompts the LLM to act as a Cyber Threat Hunter.
- Uses `.with_structured_output(DetectionResult)` to force the LLM to return a strict JSON array of threats, including the threat name, confidence score, and details.
- Includes a programmatic heuristic fallback (e.g., counting `failed_login` events) if the OpenAI API key is missing or fails.

### `src/agents/threat_intel.py`
**Purpose:** External context enrichment via the Model Context Protocol (MCP).
- If the AI detects a threat, this node acts as an MCP Client.
- It dynamically spins up `src/mcp_server.py` as a subprocess using `stdio_client` (or connects via `sse_client` if configured).
- It iterates over the detected threats and uses LLM tool-calling syntax to request data from the MCP server:
  1. **MITRE ATT&CK Mapping:** Asks the MCP server to categorize the threat behavior using the real, official MITRE STIX JSON dataset.
  2. **IP Reputation:** Uses regex to extract IPs from the threat details and asks the MCP server for AbuseIPDB scores (Strictly enforces the presence of `ABUSEIPDB_API_KEY`).
  3. **Knowledge Base:** Queries the MCP server's ChromaDB vector database for mitigation playbooks (including OWASP, CIS Benchmarks, and MITRE guides).
  4. **CVE Lookup:** Scans the logs for known software (like "apache" or "openssh") and queries the official NVD API for related vulnerabilities, utilizing the `NVD_API_KEY` for higher rate limits.
- **Memory Check:** It also scans the PostgreSQL `historical_incidents` to see if the attacking IP has been involved in previous incidents, adding a `MEMORY` note to the threat details if so.

### `src/agents/classify.py`
**Purpose:** Dynamic risk scoring and severity assignment.
- Calculates a weighted `risk_score` (0-100) based on multiple factors:
  - Base Score: Extracted directly from the LLM's confidence (`0.9` confidence = 36 points).
  - Malicious IP: Adds 30 points if the MCP server flagged the IP.
  - Previous Incidents: Adds 20 points if the IP has a history.
  - Mitre Tactic: Adds 15 points if the tactic is "Credential Access".
  - CVE: Adds 35 points if a critical CVE was found.
- Determines the final `severity` string ("Low", "Medium", "High", "Critical") based on threshold brackets.

### `src/agents/response.py`
**Purpose:** Automated response generation and DB persistence.
- Based on the `severity` and `mitre_tactic`, it generates a list of recommended `response_actions` (e.g., "Block IP at Edge Firewall").
- **Persistence:** Uses SQLAlchemy to save the final `Incident` and its associated `ThreatIntelligence` records directly into the PostgreSQL database.
- **Artifact Extraction:** Scans the cleaned logs and threat details via Regex to extract Indicators of Compromise (IoCs) such as IPs and Usernames. These are saved to the `incident_artifacts` table to enable future cross-incident correlation.

### `src/agents/approval.py`
**Purpose:** The Human-in-the-Loop breakpoint.
- Exists primarily as an interrupt node where `graph_app.compile(interrupt_before=["approval"])` pauses execution *before* it runs.
- When the graph resumes (after the analyst provides input), this node actively takes the `analyst_notes` and dynamically appends them to the bottom of the existing Markdown report.

### `src/agents/report.py`
**Purpose:** Incident summarization.
- Generates a comprehensive, human-readable Markdown report summarizing the incident, enriched threats, and recommended actions.
- Executed *before* the approval gate so that the human analyst can read the LLM's full analysis while deciding whether to approve or reject the automated actions.

---

## 3. Tooling & Infrastructure

### `src/mcp_server.py`
This is a standalone Model Context Protocol (MCP) server utilizing the `@mcp.server` decorator. It exposes four specific security tools to the LangGraph `threat_intel` agent.

**Auto-Initialization on Boot:**
- Dynamically locates and parses the official **Enterprise MITRE ATT&CK STIX 2.1 JSON** dataset. It will automatically load your locally provided dataset (e.g., `data/enterprise-attack-19.1.json`) if available, or fall back to downloading it directly from the official MITRE GitHub repository. It then builds a localized, highly-performant 1,300+ technique mapping to avoid parsing 30MB of JSON on every request.
- Iterates through the `kb/` folder and dynamically `upserts` all markdown files into ChromaDB to ensure the knowledge base is perfectly synced.

**Exposed Tools:**
1. `map_mitre_attack`: Queries the auto-generated MITRE dataset to accurately map threat behaviors (e.g., "brute force" -> "Credential Access / T1110").
2. `check_ip_reputation`: Connects directly to the **AbuseIPDB API** (`https://api.abuseipdb.com/api/v2/check`). Strictly enforces the `ABUSEIPDB_API_KEY` (returning explicit errors if missing, unless explicitly overridden by `USE_MOCK_THREAT_INTEL=true` for testing).
3. `search_knowledge_base`: Queries the local **ChromaDB** vector database. Embeds the AI's query and performs semantic similarity searches against the deeply populated `kb/` directory (which includes OWASP Top 10, CIS Benchmarks, MITRE technique deep-dives, and Incident Response Playbooks).
4. `lookup_cve`: Directly queries the **National Vulnerability Database (NVD) 2.0 API** (`services.nvd.nist.gov`). Leverages the `NVD_API_KEY` in the request headers to avoid rate limiting and fetches real CVSS base scores and severities.

### `src/database.py` & `src/models.py`
**Purpose:** Relational Data Persistence.
- `database.py` establishes the synchronous SQLAlchemy engine and provides the `get_db` dependency for FastAPI routes.
- `models.py` defines the SQL tables:
  - `Incident`: Stores the high-level incident overview, severity, status (`pending_approval`, `approved`, `rejected`), and analyst notes.
  - `AuditLog`: Tracks manual actions taken by human analysts (approvals/rejections).
  - `ThreatIntelligence`: Stores individual enriched threats mapped to a specific incident, including the IP, MITRE details, AbuseIPDB scores, and CVEs.
  - `IncidentArtifact`: Stores individual Indicators of Compromise (IoCs) extracted from an incident, such as IPs, domains, hashes, and users, enabling the correlation of threats across multiple incidents.

### `frontend/` (UI Integration)
**Purpose:** Web interface for interacting with the platform.
- **Static Mounting:** The FastAPI application (`api.py`) natively mounts the `frontend/` directory using `StaticFiles`. This allows the backend to serve the frontend directly on the same port (e.g., `8000`), eliminating CORS issues and the need for a separate frontend web server like NGINX in simple deployments.
- **Dynamic API Resolution:** The `script.js` file intelligently calculates its `API_BASE` by checking `window.location.origin`. If running locally, it defaults to `localhost:8000`. If deployed to AWS ECS, it dynamically adapts to the public DNS name of the Application Load Balancer (ALB) (e.g., `ai-defense-xxx.elb.amazonaws.com`), requiring zero code changes or environment variables for the frontend to transition from local development to cloud production.
---

## 4. Testing, CLI Simulation, & Migrations

### `main.py`
**Purpose:** CLI Simulation & Local Graph Testing.
- Provides a standalone command-line interface to execute the LangGraph workflow locally without needing to spin up the FastAPI server or trigger HTTP requests.
- Simulates multi-day "runs" of brute-force attacks to test how the AI agents track state, identify repeated threats from the same IP, and retain memory across graph executions.

---

## 5. Deployment Architecture (AWS)

The AI Cyber Defense Platform is designed to be fully deployable on **Amazon Web Services (AWS)** for robust scalability and security. The architecture leverages the following core AWS services:

### AWS RDS (Relational Database Service)
- **Role:** Managed PostgreSQL Database.
- **Purpose:** Completely replaces local/Dockerized Postgres. It persistently stores `Incidents`, `ThreatIntelligence`, `AuditLogs`, and `IncidentArtifacts`. It also serves as the highly available state-store (Checkpointer) for LangGraph, ensuring no incident states are lost during container restarts or scale-out events.

### AWS ECS (Elastic Container Service) & ECR
- **Role:** Container Orchestration & Image Registry.
- **Purpose & Configuration:** 
  - **Amazon ECR:** Stores the versioned multi-architecture Docker image for the AI Cyber Defense Platform.
  - **Amazon ECS Fargate:** Runs the application as a serverless container without requiring EC2 instance management.
  - **Single-Container Deployment:** The Docker image hosts both the FastAPI backend (port 8000) and the MCP server (port 8001). The FastAPI application communicates directly with the embedded MCP server over localhost:8001/sse, eliminating inter-container network overhead while keeping the deployment simple.
  - **Application Load Balancer (ALB):** An internet-facing ALB routes external HTTP/HTTPS traffic to the FastAPI service on port 8000 and continuously performs health checks using the `/health` endpoint.

#### Architecture Diagram

```text
                    Internet
                         │
                         ▼
            Application Load Balancer
                         │
                         ▼
                 ECS Fargate Task
                ┌───────────────────┐
                │   Docker Image    │
                │                   │
                │ FastAPI (8000)    │
                │ MCP Server (8001) │
                └───────────────────┘
                         │
                         ▼
               Amazon RDS PostgreSQL
      Incidents | Threat Intel | Audit Logs
       LangGraph Checkpoints | Artifacts
```

---

## 6. Continuous Deployment & Post-Launch Refactoring

A true hallmark of modern cloud infrastructure is the ability to adapt to user feedback post-launch without experiencing downtime. Shortly after the initial AWS ECS deployment, we identified several critical workflow improvements and executed a live rolling update.

### Post-Launch Architecture Refactoring
- **LangGraph Node Re-Routing:** During initial testing, the AI generated the Incident Report *after* the Human-in-the-Loop approval gate. We quickly realized analysts needed to read the report *to make* their approval decision. We dynamically re-routed the Directed Acyclic Graph (DAG) so that the `report` node executes before `approval`, instantly empowering analysts with full context.
- **Dynamic State Injection:** We updated `api.py` and `approval.py` so that when an analyst finally approves an incident via the API, their manual `analyst_notes` are instantly appended to the pre-existing Markdown report stored in the PostgreSQL Checkpointer.
- **UI Markdown Rendering:** We upgraded the frontend to natively parse the LLM's Markdown output into beautifully formatted HTML (using `marked.js`), instantly turning raw text into a professional, highly-readable interface.

### The Rolling Update Execution
Because the platform is containerized and hosted on AWS ECS Fargate, pushing these architectural changes was completely seamless:
1. We rebuilt the multi-architecture image using `docker buildx` to ensure compatibility with AWS Fargate.
2. We pushed the updated image to Amazon ECR, utilizing the `:latest` tag for a continuous deployment pipeline.
3. We updated the ECS Task Definition to pull `:latest` rather than a hardcoded `sha256` digest, and triggered a **Force New Deployment**.
4. AWS ECS gracefully spun up the newly patched containers, verified their health via the `/health` endpoint, and seamlessly drained connections from the old containers, resulting in **zero downtime** for the live Load Balancer URL.