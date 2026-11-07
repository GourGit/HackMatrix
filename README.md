# TrustLens Project Knowledge Base

This folder is the source of truth for building **TrustLens**, an AI-powered web threat detection and digital trust intelligence platform.

## How to use this folder with an AI coding assistant

1. Open the `TrustLens_Project_Pack` folder as the project workspace.
2. Give the assistant `MASTER_BUILD_PROMPT.md` first.
3. Ask it to read `docs/` before changing code.
4. Implement one milestone at a time. Do not ask it to generate the entire application in one pass.
5. Require tests and a short change summary after every milestone.
6. Keep these documents updated whenever an architectural decision changes.

Suggested first instruction:

> Read `MASTER_BUILD_PROMPT.md` and every Markdown file in `docs/`. Treat these documents as the project specification and source of truth. First inspect the repository, identify what already exists, report conflicts or missing prerequisites, and propose the smallest safe implementation milestone. Do not overwrite working code or invent completed integrations.

## Project summary

TrustLens investigates a submitted website using six deterministic security analyzers coordinated by Python `asyncio`. A deterministic risk engine calculates the assessment. One OpenRouter-backed AI analyst explains the evidence; it does not decide or override the score.

### Architecture at a glance

- Frontend: React, TypeScript, Tailwind CSS
- API: Python, FastAPI, Pydantic
- Orchestration: `asyncio`
- Analysis: six deterministic agents
- AI explanation: OpenRouter
- Persistence: PostgreSQL, SQLAlchemy, Alembic
- Testing: pytest, pytest-asyncio, frontend test tooling
- Scanning: isolated worker with restricted outbound network access

## Documentation index

| File | Purpose |
|---|---|
| `MASTER_BUILD_PROMPT.md` | Detailed prompt to give an AI coding assistant |
| `docs/prd.md` | Product requirements and MVP |
| `docs/architecture.md` | System architecture and data flow |
| `docs/design.md` | UI/UX specification |
| `docs/database.md` | Relational schema and persistence |
| `docs/api.md` | REST contracts and OpenRouter integration |
| `docs/authentication and security.md` | Authentication, secrets, SSRF and security controls |
| `docs/integrations.md` | External providers and integration boundaries |
| `docs/agents.md` | Agent roles, contracts and orchestration |
| `docs/mcp-connection.md` | Optional MCP server and IDE integration |
| `docs/fetures-development.md` | Prioritized implementation roadmap |
| `docs/testing and QA.md` | Test strategy and acceptance criteria |
| `docs/debugging.md` | Logging and troubleshooting |

## Important safety and product principles

- A valid HTTPS certificate does not prove a website is legitimate.
- No automated scan can guarantee that a website is safe.
- Missing or unavailable evidence must never be represented as a clean result.
- A provider outage must not stop independent analyzers.
- The AI analyst explains evidence; it cannot invent findings or change the deterministic risk score.
- URL scanning is an SSRF-sensitive operation. Run outbound inspection in an isolated worker with network-level egress controls.
- Do not claim an integration works until it has been implemented and tested with real or documented sandbox credentials.
