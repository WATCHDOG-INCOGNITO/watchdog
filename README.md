# Watchdog

**AI-powered autonomous penetration testing agent** that discovers, chains, and exploits vulnerabilities — just like a human red-teamer but at machine speed.

Watchdog combines a multi-agent LLM architecture with a structured Knowledge Base, a living memory system, and a visual Discovery Tree to autonomously perform deep, multi-step exploit chains against web applications.


## Key Features

### Multi-Agent Swarm Architecture
Multiple specialized LLM workers (Planner, Explorer, Executor) operate in parallel through a Discovery Queue. Each worker picks a frontier node — an endpoint, a clue, or a vulnerability — and pushes deeper, automatically chaining findings into complex attack paths.

### Discovery Tree
Every reconnaissance step, vulnerability, exploit attempt, and captured flag is recorded as a node in a tree structure. The tree grows organically as the agent explores, creating a full audit trail of the attack surface.

### Knowledge Base (KB)
A curated, searchable library of **27 vulnerability categories** and **44+ exploit techniques** modeled after [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings). Each technique includes preconditions, code templates, step-by-step instructions, and metadata — enabling the agent to recognize and apply known patterns instantly.

### Living KB
Host-specific memory that persists across scans. Successful payloads, dead-end paths, target profiles, and discovered credentials are stored per-target. When revisiting a host, the agent picks up where it left off instead of starting from scratch.

### Real-Time Dashboard
A React-based frontend with:
- **Canvas-style graph visualization** of the Discovery Tree (node-graph UI inspired by Obsidian)
- **Node detail panel** — click any node to inspect findings, evidence, and exploit context
- **Live scan monitoring** via WebSocket with status indicators
- **Scan history** grouped by target URL for easy navigation

### MCP Tool Server
A Model Context Protocol (MCP) server exposing 28+ tools for HTTP requests, KB search, source analysis, discovery management, session/secret storage, and more. Works both as an API for LLM agents and as a CLI for manual pentesting.

---

## Architecture

┌─────────────────────────────────────────────────┐
│                   Frontend (React)              │
│         Canvas Graph · Detail Panel · Live WS   │
└────────────────────┬────────────────────────────┘
                     │ REST + WebSocket
┌────────────────────▼────────────────────────────┐
│              Backend (Django + DRF)              │
│    ScanRun · Candidate · Finding · Evidence      │
│    DiscoveryNode · TargetProfile · DeadEnd       │
├──────────────┬──────────────┬───────────────────┤
│  MCP Server  │  Agent Core  │  Knowledge Base   │
│  (28+ tools) │  (Swarm LLM) │  (27 vuln types)  │
└──────┬───────┴──────┬───────┴───────┬───────────┘
       │              │               │
  HTTP Requests   Discovery Queue   pgvector
  to targets      (async workers)   (embeddings)
```

| Layer | Tech | Role |
|---|---|---|
| **Frontend** | React 18, Canvas API | Discovery Tree graph, live dashboard |
| **Backend** | Django 5, DRF, Channels | REST API, WebSocket, scan orchestration |
| **Database** | PostgreSQL 16 + pgvector | Models, embeddings, full-text search |
| **Agent** | Anthropic Claude API | Multi-agent LLM swarm (Planner → Explorer → Executor) |
| **MCP** | SSE transport | Tool server for agent ↔ backend communication |
| **Infra** | Docker Compose | One-command local deployment |

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- (Optional) `ANTHROPIC_API_KEY` for autonomous agent mode

### Run

```bash
git clone <repo-url> watchdog && cd watchdog
docker compose up -d --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000/api/ |
| MCP Server | http://localhost:8889 |

### Seed the Knowledge Base

```bash
docker exec watchdog-backend-1 python manage.py seed_knowledge
```

### Launch a Scan

```bash
# Via API
curl -X POST http://localhost:8000/api/scan-runs/ \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://target:8080", "mode": "discovery"}'

# Or use the frontend at http://localhost:3000
```

---

### Scan option
- `Low Cost`: Uses lighter models for mapping and reporting, while keeping core security reasoning on Sonnet.
- `Balanced`: Uses Sonnet for most discovery and verification steps, with lighter models for support roles.
- `High Performance`: Uses stronger models for complex hypotheses, exploit execution, and confirmation.
- `Advanced Settings`: You can customize the model for each discovery role individually.


## Knowledge Base

27 vulnerability categories with sub-technique classification:

| Category | Examples |
|---|---|
| `sqli` | type confusion bypass, PDO smuggling, reflection invocation |
| `xss` | DOM-based, stored, filter evasion |
| `ssrf` | internal service access, cloud metadata |
| `lfi` | path traversal, PHP wrapper, include injection |
| `rce` | deserialization, template injection, command injection |
| `auth_bypass` | JWT forgery, session fixation, OAuth redirect |
| `idor` | direct object reference, UUID enumeration |
| `file_upload` | extension bypass, polyglot, content-type confusion |
| ... | 19 more categories |

Each technique stores:
- **Preconditions** — when the technique applies
- **Code template** — ready-to-use exploit code
- **Step-by-step guide** — ordered exploitation steps
- **Tags & metadata** — for semantic search and similarity matching

---

## Discovery Tree

The Discovery Tree is the core data structure driving exploration:

```
ROOT: http://target (depth 0)
├── ENDPOINT: /api/login (depth 1)
│   ├── VULN: Werkzeug debugger info leak (depth 2)
│   │   └── CLUE: broken sanitize → SQLi vector (depth 3)
│   │       └── EXPLOIT_STEP: type confusion bypass (depth 4)
│   └── CLUE: JWT secret leaked (depth 2)
│       └── EXPLOIT_STEP: auth token forgery (depth 3)
├── ENDPOINT: /internal/render (depth 1)
│   └── EXPLOIT_STEP: LFI via include() (depth 2)
│       └── FLAG: captured! (depth 3) ★
```

Node types: `root` → `endpoint` → `vuln` / `clue` → `exploit_step` → `flag`

Workers pop frontier nodes from the queue, explore them, and push children — creating a breadth-first, multi-path attack graph.

---

## Validated Results

Watchdog has been tested against CTF challenges from CodeGate 2023–2026 finals, successfully identifying and exploiting multi-step vulnerability chains including:

- **Auth token forgery** via leaked signing secrets
- **SQL injection** through type-confusion sanitization bypass
- **Local File Inclusion** via PHP `include()` with DB-controlled paths
- **SSRF → internal service access** chains
- **Deserialization RCE** via crafted payloads
- **Session fixation** and **IDOR** exploit chains

---

## Project Structure

```
watchdog/
├── backend/backend/          # Django API + Agent core
│   ├── api/                  # Models, views, serializers, mcp_agent.py
│   ├── watchdog_mcp/         # MCP tool server (28+ tools)
│   └── config/               # Django settings
├── frontend/                 # React 18 SPA
│   └── src/App.jsx           # Dashboard + Discovery Tree canvas
├── agent/                    # Agent configs & eval harness
├── docker/                   # E2E test compose
├── infra/                    # CI/CD guides
├── secrets/                  # API keys (gitignored)
└── docker-compose.yml        # One-command deployment
```

---

## Development

```bash
# Backend (local)
cd backend/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate && python manage.py runserver

# Frontend (local)
cd frontend
npm install && npm start
```

### CI/CD

- **CI**: gitleaks secret scan, Trivy image scan, SBOM generation, E2E smoke tests
- **CD**: GitHub Environments with staging (auto) and production (approval-gated)

---

## License

This project is for research and educational purposes.
