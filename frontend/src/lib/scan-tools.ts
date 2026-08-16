// The native scanner tools On-Demand Scan can trigger per target -- matches
// backend/app/scanners/parsers.PARSER_MAP's on-demand subset (checkov/tfsec
// are IaC-specific and triggered from their own surfaces, not here).
// Shared between the per-target scan trigger (targets/[id]/scan-buttons.tsx)
// and the Scans page rebuild (#120) so both dispatch the same tool set
// instead of two hand-maintained copies drifting apart.
// modelscan (#186) is included but only does anything on repos detected as
// AI/ML (#185) -- on any other target the backend records a completed scan
// with zero findings rather than failing, so it is safe to offer everywhere.
export const SCAN_TOOLS = ["semgrep", "gitleaks", "trivy", "trivy-license", "gosec", "modelscan", "semgrep-llm"] as const;
