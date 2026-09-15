/**
 * Plain-language help copy for the product's feature pages, in one place so a
 * heading, a hint and anything else that describes a feature stay in step.
 *
 * `docsUrl` is only set where the published documentation site actually has a
 * page for that feature (verified against geekshiv.github.io/toleman). A
 * feature with no published page omits the field rather than pointing a reader
 * at a 404; `HelpHint` renders the hint without a "Learn more" link in that
 * case.
 */

export interface HelpTopic {
  /**
   * Feature name. Also drives the hint's accessible name ("About <title>"),
   * so keep it matching the page heading it sits next to.
   */
  title: string;
  /** One or two sentences: what the page answers, and who it is for. */
  body: string;
  /** Published documentation page for the feature, when one exists. */
  docsUrl?: string;
}

export type HelpFeatureKey =
  | "targets"
  | "findings"
  | "ai-security"
  | "sbom"
  | "guardrails"
  | "api-discovery";

const DOCS = "https://geekshiv.github.io/toleman/documentation";

export const HELP_CONTENT: Record<HelpFeatureKey, HelpTopic> = {
  targets: {
    title: "Targets",
    body: "Every repository connected for scanning, with its GitHub connection state, criticality and latest scan. Use it to bring a new repo under scanning, or to confirm the coverage you think you have.",
    docsUrl: `${DOCS}/github-integration/targets-and-groups`,
  },
  findings: {
    title: "Findings",
    body: "One queue of every vulnerability found across your targets, ordered by severity, target criticality and evidence that the flaw is exploited in the wild. Use it to decide what to fix first and to record a triage decision.",
    docsUrl: `${DOCS}/findings/lifecycle-and-scoring`,
  },
  "ai-security": {
    title: "AI Security",
    body: "Repositories that ship AI/ML code, and what scanning them found: unsafe model deserialization and risky LLM call patterns that general-purpose SAST does not look for. Use it to see which AI code paths carry risk.",
    docsUrl: `${DOCS}/scanning/ai-security`,
  },
  sbom: {
    title: "SBOM & OSS Vulnerabilities",
    body: "The dependency inventory for a target and the known vulnerabilities in it, built from GitHub's dependency graph and any CycloneDX or SPDX document you upload. Use it when an advisory lands and you need to know whether you run an affected version.",
    docsUrl: `${DOCS}/scanning/sbom`,
  },
  guardrails: {
    title: "Guardrails",
    body: "The rules that decide how findings are handled: repo groups, SLA clocks, false-positive suppressions, pull request policy gates and risk-scoring weights. Use it to change what the platform blocks, escalates or ignores.",
    docsUrl: `${DOCS}/github-integration/pr-guardrail`,
  },
  "api-discovery": {
    title: "API Discovery",
    body: "The HTTP routes found in a target's source, each with the file and line it came from, alongside what active scanning found against them. Use it to spot endpoints that are reachable but were never reviewed.",
    docsUrl: `${DOCS}/scanning/api-discovery-and-scanning`,
  },
};
