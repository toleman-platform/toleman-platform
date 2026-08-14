// The native scanner tools On-Demand Scan can trigger per target -- matches
// backend/app/scanners/parsers.PARSER_MAP's on-demand subset (checkov/tfsec
// are IaC-specific and triggered from their own surfaces, not here).
// Shared between the per-target scan trigger (targets/[id]/scan-buttons.tsx)
// and the Scans page rebuild (#120) so both dispatch the same tool set
// instead of two hand-maintained copies drifting apart.
export const SCAN_TOOLS = ["semgrep", "gitleaks", "trivy", "trivy-license", "gosec"] as const;
