import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/quickstart',
        'getting-started/architecture-overview',
      ],
    },
    {
      type: 'category',
      label: 'GitHub Integration',
      items: [
        'github-integration/connecting-github',
        'github-integration/targets-and-groups',
        'github-integration/pipeline-integration',
        'github-integration/pr-guardrail',
        'github-integration/webhooks',
      ],
    },
    {
      type: 'category',
      label: 'Scanning',
      items: [
        'scanning/scanners',
        'scanning/api-discovery-and-scanning',
        'scanning/sbom',
      ],
    },
    {
      type: 'category',
      label: 'Findings & Triage',
      items: [
        'findings/lifecycle-and-scoring',
        'findings/enrichment-and-ai-analysis',
        'findings/sla-and-policy',
      ],
    },
    {
      type: 'category',
      label: 'Admin & Management',
      items: [
        'admin/users-and-roles',
        'admin/workspaces-and-api-keys',
        'admin/platform-config',
        'admin/audit-and-compliance',
      ],
    },
    {
      type: 'category',
      label: 'Dashboard',
      items: ['dashboard/widgets-and-security-score'],
    },
    {
      type: 'category',
      label: 'Reference',
      items: ['reference/api', 'reference/mcp-server'],
    },
  ],
};

export default sidebars;
