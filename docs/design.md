# TrustLens — UI/UX Design Specification

## 1. Design objective

Make complex security analysis understandable without hiding uncertainty. The interface should feel like a modern security intelligence console: calm, credible, clean and responsive. Avoid excessive neon, alarmist language and decorative dashboards that do not explain evidence.

## 2. Information architecture

Primary navigation:
- Overview
- Scan a URL
- Scan History
- Threat Reports
- About / Methodology

For the hackathon MVP, prioritize Overview, Scanner and Scan Result.

## 3. Main screens

### A. Landing / Overview
Components:
- TrustLens logo and concise value proposition
- prominent URL input
- “Analyze website” primary action
- explanation of the six analysis dimensions
- recent scans (if history is enabled)
- disclaimer: assessments are indicators, not a guarantee

### B. Scanner
Components:
- URL input with protocol guidance
- validation errors shown inline
- consent/disclosure for external reputation-provider sharing where applicable
- scan button
- sample/demo URL option using safe fixtures

### C. Investigation progress
Display six agent rows/cards:
- agent name and icon
- state: queued, running, completed, partial, unavailable, failed
- short description
- elapsed time
- count of findings

Do not fabricate progress. Render actual backend state. If polling is used, show last-updated time.

### D. Digital Trust Passport
Top section:
- domain and normalized URL
- scan time
- risk score or “Insufficient evidence”
- category
- evidence coverage
- confidence
- concise AI summary, clearly labeled as AI-generated

Main sections:
1. Key findings
2. Agent-by-agent results
3. Domain and DNS details
4. TLS certificate details
5. Website configuration checks
6. Brand similarity indicators
7. Threat intelligence sources
8. Unavailable checks and limitations
9. Recommendations

### E. Threat report form
Fields:
- URL/domain
- report category
- optional description
- optional evidence reference
- confirmation that reporter is not submitting sensitive personal information

Reports must be rate-limited and moderated. Do not publish unverified accusations as confirmed facts.

## 4. Visual language

- Neutral dark or light base with strong contrast.
- Use semantic colors sparingly: red for confirmed high-risk signals, amber for suspicious/uncertain, green for a completed clean check, gray for unavailable.
- Never use green “safe” status for an incomplete scan.
- Score must be accompanied by coverage and methodology link.
- Use clear typography and compact evidence cards.
- Use responsive grids; stack cards on mobile.

## 5. Reusable components

- `AppShell`
- `Navbar`
- `UrlScanForm`
- `ScanStatusBanner`
- `AgentStatusCard`
- `AgentProgressList`
- `RiskScoreCard`
- `EvidenceCoverage`
- `FindingCard`
- `EvidenceSourceChip`
- `CertificateDetails`
- `DomainDetails`
- `AIExplanationCard`
- `LimitationsPanel`
- `RecommendationList`
- `ScanHistoryTable`
- `EmptyState`
- `ErrorState`
- `LoadingSkeleton`
- `Disclaimer`

## 6. User journey

1. User opens dashboard.
2. User pastes a link.
3. Frontend validates basic syntax; backend performs authoritative validation.
4. User starts scan.
5. Frontend receives `scan_id`.
6. Progress page polls scan state.
7. Completed result renders score, coverage, findings and limitations.
8. User expands agent evidence and follows recommendations.
9. User may submit a report.

## 7. Content and accessibility

- Use plain language: “Certificate hostname matched” rather than unexplained jargon.
- Add “Why this matters” explanations.
- Explain unavailable provider checks.
- Keyboard-operable forms and controls.
- Visible focus states.
- Accessible labels and semantic headings.
- Do not rely on color alone.
- Provide loading, empty, error and partial-result states.
- Avoid overstating “AI detected” when a deterministic provider produced the signal.

## 8. Responsive behavior

Desktop: two-column dashboard and evidence layout.

Tablet: condensed two-column cards.

Mobile: single-column layout, sticky scan action only if it does not obscure content, horizontally scrollable tables avoided in favor of stacked cards.
