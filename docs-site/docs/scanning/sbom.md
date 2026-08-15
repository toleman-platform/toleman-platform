---
sidebar_position: 3
---

# SBOM

Rikugan generates a Software Bill of Materials per target, org-wide, or for a repo group — async, same tracking-row + poll pattern as scans.

```bash
POST /api/sbom/run?target_id=1
GET  /api/sbom/{target_id}
```

## Export

Export uses the platform's shared downloadable-export pattern (`Content-Disposition: attachment`) — the frontend fetches with credentials, turns the response into a blob, and triggers a synthetic download click. Both per-target and org-wide export are available.

## OSS vulnerability tab

SBOM components with known vulnerabilities reuse the same Findings table/row components as the main Findings page (`findings-list.tsx`/`finding-row.tsx`) — one shared UI stack rather than a bespoke SBOM-only table.
