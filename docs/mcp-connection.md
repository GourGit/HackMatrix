# TrustLens — MCP Connection Specification

## 1. Purpose

Model Context Protocol (MCP) is an optional developer/AI-assistant integration. It is not required for the TrustLens runtime MVP and must not become a shortcut around scanner security controls.

An MCP server may expose safe, read-only operations to an IDE assistant or authorized analyst.

## 2. Suggested MCP server

Implement later as a separate process, for example:

`backend/mcp_server/server.py`

Transport:
- stdio for local IDE development
- authenticated HTTP transport only if remote access is genuinely required

Use a maintained MCP SDK and follow its current protocol version and security guidance.

## 3. Candidate tools

### `get_scan`
Input: `scan_id`
Output: scan status and high-level assessment, subject to caller authorization.

### `get_agent_results`
Input: `scan_id`, optional `agent_name`
Output: normalized checks and findings.

### `get_domain_intelligence`
Input: normalized hostname
Output: stored DNS/RDAP observations. This tool should read existing data, not initiate arbitrary network scans by default.

### `get_threat_reports`
Input: domain and pagination
Output: moderated reports only.

### `explain_assessment`
Input: scan ID
Output: stored explanation and evidence references. Do not permit arbitrary prompt override.

## 4. Resources

Potential read-only resources:
- `trustlens://scans/{scan_id}`
- `trustlens://scans/{scan_id}/agents`
- `trustlens://domains/{domain}/reports`
- `trustlens://methodology/risk-scoring`

Resources must enforce authorization and return only data the user may access.

## 5. Security boundaries

- Do not expose API keys, database credentials or internal environment variables.
- Do not expose arbitrary shell or filesystem tools.
- Do not let MCP callers request arbitrary URL fetches.
- Require authorization for user-specific scans.
- Validate all tool arguments.
- Rate-limit tools.
- Log tool invocation metadata without logging secrets.
- Treat tool output as untrusted input to the consuming model.
- Keep write operations out of the initial MCP server.

## 6. IDE integration

For local development:
1. Install a compatible MCP client/IDE.
2. Configure the local server command and environment using the IDE's supported configuration format.
3. Pass only required environment variables.
4. Start with read-only tools.
5. Test authorization and error handling.
6. Never commit local MCP configuration containing secrets.

Exact configuration differs by IDE and MCP SDK version. Follow the current official documentation for the chosen client rather than copying stale configuration.

## 7. MVP decision

MCP is P2/future scope. Complete the core API, agents, risk engine and frontend first. Add MCP only when the core system is stable.
