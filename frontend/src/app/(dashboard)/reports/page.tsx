"use client";

import { useEffect, useMemo, useState } from "react";
import { api, type Group, type PostureReportOptions, type ReportSection, type Target } from "@/lib/api";
import { useAsyncData } from "@/hooks/use-async-data";
import { FINDING_STATE_ORDER, SEVERITY_ORDER } from "@/lib/severity";
import { TargetPicker, ALL_TARGETS } from "@/components/features/targets";
import { MultiSelectDropdown } from "@/components/multi-select-filter";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { AlertBanner } from "@/components/ui/alert-banner";
import {
  DocGenField,
  DocGenSelect,
  DocGenToggle,
  DocumentGeneratorPanel,
  WhatsIncludedCard,
} from "@/components/features/intelligence";

type ExportFormat = "csv" | "pdf";

// What the report contains when the section catalog can't be fetched. The
// backend defaults to every section, so the export still works; this is the
// pre-#302 wording, used only so the "What's included" card degrades to a
// true (if non-specific) statement rather than an empty or wrong one.
const FALLBACK_INCLUDED = [
  "Finding counts by severity and triage state, per target and totals",
  "Open-finding age / SLA buckets (0-7d, 8-30d, 31-90d, 90d+)",
  "Scan history and coverage; latest run per tool, per target",
  "SBOM component summary per target (when SBOM data has been generated)",
];

export default function ReportsPage() {
  const { data: targetsData } = useAsyncData<Target[]>(() => api.targets());
  const targets = targetsData ?? [];
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null);
  const targetId = selectedTargetId ?? (targets.length > 0 ? ALL_TARGETS : null);
  const setTargetId = setSelectedTargetId;
  const [format, setFormat] = useState<ExportFormat>("csv");
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastDownload, setLastDownload] = useState<string | null>(null);

  // (#302) Filter facets, the same ones the Findings page filters by, so the
  // report can be scoped the way the findings themselves can be.
  const [groups, setGroups] = useState<Group[]>([]);
  const [tools, setTools] = useState<string[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [environments, setEnvironments] = useState<string[]>([]);
  const [owners, setOwners] = useState<string[]>([]);

  const [groupId, setGroupId] = useState("");
  const [environment, setEnvironment] = useState("");
  const [owner, setOwner] = useState("");
  const [severity, setSeverity] = useState<string[]>([]);
  const [state, setState] = useState<string[]>([]);
  const [tool, setTool] = useState<string[]>([]);
  const [category, setCategory] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  // (#302) Section selection. The catalog comes from the backend so this
  // page can only ever offer sections the renderers know how to produce;
  // everything starts checked, which is the same report this page produced
  // before sections were selectable.
  const [sectionCatalog, setSectionCatalog] = useState<ReportSection[]>([]);
  const [sections, setSections] = useState<string[]>([]);

  useEffect(() => {
    // Facets are decoration on the generator, not its subject: one of them
    // failing should cost the operator that one filter, not the page.
    api.groups().then(setGroups).catch(() => setGroups([]));
    api.findingTools().then(setTools).catch(() => setTools([]));
    api
      .findingCategories()
      .then((facets) => setCategories(facets.map((f) => f.category)))
      .catch(() => setCategories([]));
    api.findingEnvironments().then(setEnvironments).catch(() => setEnvironments([]));
    api.findingOwners().then(setOwners).catch(() => setOwners([]));
    api
      .reportSections()
      .then((catalog) => {
        setSectionCatalog(catalog);
        setSections(catalog.map((s) => s.key));
      })
      .catch(() => setSectionCatalog([]));
  }, []);

  const currentTarget = targets.find((t) => t.id === targetId);
  const scopeLabel =
    targetId === ALL_TARGETS ? "org-wide" : (currentTarget?.name ?? "target");

  const allSectionsChosen = sectionCatalog.length > 0 && sections.length === sectionCatalog.length;
  const chosenSections = useMemo(
    () => sectionCatalog.filter((s) => sections.includes(s.key)),
    [sectionCatalog, sections],
  );
  const excludedSections = useMemo(
    () => sectionCatalog.filter((s) => !sections.includes(s.key)),
    [sectionCatalog, sections],
  );

  // What the operator has actually narrowed, phrased the way the generated
  // document's own "Applied Filters" block phrases it. Shown here too so the
  // scope is visible *before* the download, not only inside it.
  const activeFilters = useMemo(() => {
    const parts: string[] = [];
    const groupName = groups.find((g) => String(g.id) === groupId)?.name;
    if (groupName) parts.push(`group ${groupName}`);
    if (environment) parts.push(`environment ${environment}`);
    if (owner) parts.push(`owner ${owner}`);
    if (severity.length) parts.push(`severity ${severity.join("/")}`);
    if (state.length) parts.push(`state ${state.join("/")}`);
    if (tool.length) parts.push(`tool ${tool.join("/")}`);
    if (category) parts.push(`category ${category}`);
    if (dateFrom || dateTo) parts.push(`window ${dateFrom || "(open)"} to ${dateTo || "(open)"}`);
    return parts;
  }, [groups, groupId, environment, owner, severity, state, tool, category, dateFrom, dateTo]);

  const invalidWindow = !!dateFrom && !!dateTo && dateFrom > dateTo;

  function clearFilters() {
    setGroupId("");
    setEnvironment("");
    setOwner("");
    setSeverity([]);
    setState([]);
    setTool([]);
    setCategory("");
    setDateFrom("");
    setDateTo("");
  }

  async function generate() {
    if (targetId === null) return;
    setExporting(true);
    setError(null);
    setLastDownload(null);
    try {
      const options: PostureReportOptions = {
        group_id: groupId ? Number(groupId) : undefined,
        environment: environment || undefined,
        owner: owner || undefined,
        severity: severity.length ? severity : undefined,
        state: state.length ? state : undefined,
        tool: tool.length ? tool : undefined,
        category: category || undefined,
        date_from: dateFrom || undefined,
        date_to: dateTo || undefined,
        // Everything selected means "no section filter": let the backend
        // apply its own default rather than pinning today's section list
        // into every request this page makes. Same for an empty selection,
        // which here only happens when the catalog never loaded, never as a
        // deliberate "report with nothing in it" (Generate is disabled for
        // that case).
        sections: allSectionsChosen || sections.length === 0 ? undefined : sections,
      };
      const { blob, filename: serverFilename } = await api.exportPostureReport(targetId, format, options);
      const url = URL.createObjectURL(blob);
      // The backend names the file (scope, filtered, section count, date).
      // The local fallback is only for a response that arrived without a
      // Content-Disposition at all.
      const dateSlug = new Date().toISOString().slice(0, 10);
      const filename =
        serverFilename || `toleman-posture-report-${scopeLabel.replace(/\s+/g, "-")}-${dateSlug}.${format}`;
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setLastDownload(filename);
    } catch (e) {
      setError(e instanceof Error ? e.message : "report generation failed");
    } finally {
      setExporting(false);
    }
  }

  const steps = [
    <DocGenField key="scope" label="Scope">
      <TargetPicker targets={targets} value={targetId} onChange={setTargetId} allowAll />
    </DocGenField>,
    <DocGenField key="format" label="Format">
      <DocGenToggle
        options={[
          { value: "csv", label: "CSV" },
          { value: "pdf", label: "PDF" },
        ]}
        value={format}
        onChange={(v) => setFormat(v as ExportFormat)}
      />
    </DocGenField>,
  ];

  // A facet with nothing in it is not offered at all: an "All environments"
  // dropdown with no environments behind it is a control that looks like it
  // filters and cannot.
  if (groups.length > 0) {
    steps.push(
      <DocGenField key="group" label="Repo group">
        <DocGenSelect
          ariaLabel="Filter by repo group"
          placeholder="All groups"
          value={groupId}
          onChange={setGroupId}
          options={groups.map((g) => ({ value: String(g.id), label: g.name }))}
        />
      </DocGenField>,
    );
  }
  if (environments.length > 0) {
    steps.push(
      <DocGenField key="environment" label="Environment">
        <DocGenSelect
          ariaLabel="Filter by environment"
          placeholder="All environments"
          value={environment}
          onChange={setEnvironment}
          options={environments.map((e) => ({ value: e, label: e }))}
        />
      </DocGenField>,
    );
  }
  if (owners.length > 0) {
    steps.push(
      <DocGenField key="owner" label="Owner">
        <DocGenSelect
          ariaLabel="Filter by owner"
          placeholder="All owners"
          value={owner}
          onChange={setOwner}
          options={owners.map((o) => ({ value: o, label: o }))}
        />
      </DocGenField>,
    );
  }

  steps.push(
    <DocGenField key="severity" label="Severity">
      <MultiSelectDropdown
        label="All severities"
        options={SEVERITY_ORDER.map((s) => ({ value: s, label: s }))}
        selected={severity}
        onChange={setSeverity}
      />
    </DocGenField>,
    <DocGenField key="state" label="Finding state">
      <MultiSelectDropdown
        label="All states"
        options={FINDING_STATE_ORDER.map((s) => ({ value: s, label: s }))}
        selected={state}
        onChange={setState}
      />
    </DocGenField>,
  );

  if (tools.length > 0) {
    steps.push(
      <DocGenField key="tool" label="Tool">
        <MultiSelectDropdown
          label="All tools"
          options={tools.map((t) => ({ value: t, label: t }))}
          selected={tool}
          onChange={setTool}
        />
      </DocGenField>,
    );
  }
  if (categories.length > 0) {
    steps.push(
      <DocGenField key="category" label="Category">
        <DocGenSelect
          ariaLabel="Filter by category"
          placeholder="All categories"
          value={category}
          onChange={setCategory}
          options={categories.map((c) => ({ value: c, label: c }))}
        />
      </DocGenField>,
    );
  }

  steps.push(
    <DocGenField key="window" label="Finding window">
      <div className="flex items-center gap-1.5">
        <Input
          type="date"
          aria-label="Finding window from date"
          className="h-8 w-[9.5rem] bg-secondary text-xs"
          value={dateFrom}
          onChange={(e) => setDateFrom(e.target.value)}
        />
        <span className="text-xs text-muted-foreground">to</span>
        <Input
          type="date"
          aria-label="Finding window to date"
          className="h-8 w-[9.5rem] bg-secondary text-xs"
          value={dateTo}
          onChange={(e) => setDateTo(e.target.value)}
        />
      </div>
    </DocGenField>,
  );

  if (sectionCatalog.length > 0) {
    steps.push(
      <DocGenField key="sections" label="Sections">
        <MultiSelectDropdown
          label="Sections"
          ariaLabel="Choose report sections"
          options={sectionCatalog.map((s) => ({ value: s.key, label: s.label }))}
          selected={sections}
          onChange={setSections}
        />
      </DocGenField>,
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Compliance Reports"
        description="Audit-ready posture export built from live workspace data, finding counts by severity and state, SLA age, scan coverage, and SBOM summary. Narrow it with the same filters as the Findings page, and pick the sections you need; whatever you choose is recorded on the document itself."
      />

      <DocumentGeneratorPanel
        layout="inline"
        steps={steps}
        generateLabel="Generate Report"
        onGenerate={generate}
        generating={exporting}
        generateDisabled={
          targetId === null || (sectionCatalog.length > 0 && sections.length === 0) || invalidWindow
        }
        extra={
          <div className="basis-full">
            <p className="text-xs text-muted-foreground">
              Scope: <span className="font-medium text-foreground">{scopeLabel}</span>
              {targetId === ALL_TARGETS
                ? ", every target in the platform"
                : currentTarget
                  ? `, default branch (${currentTarget.default_branch})`
                  : ""}
              {activeFilters.length > 0 ? (
                <>
                  {" "}
                  &middot; Filters:{" "}
                  <span className="font-medium text-foreground">{activeFilters.join("; ")}</span>
                </>
              ) : (
                " · Unfiltered"
              )}
            </p>

            {activeFilters.length > 0 && (
              <button
                onClick={clearFilters}
                className="mt-1 text-xs text-muted-foreground underline hover:text-foreground"
              >
                Clear filters
              </button>
            )}

            {sections.length === 0 && sectionCatalog.length > 0 && (
              <p className="mt-2 text-sm text-destructive">
                Pick at least one section to include.
              </p>
            )}
            {invalidWindow && (
              <p className="mt-2 text-sm text-destructive">
                The finding window&apos;s start date must be on or before its end date.
              </p>
            )}

            {error && (
              <AlertBanner tone="critical" className="mt-2">
                {error}
              </AlertBanner>
            )}
            {!error && lastDownload && (
              <AlertBanner tone="positive" className="mt-2" title="Report Exported">
                Downloaded <span className="font-mono font-medium">{lastDownload}</span>
              </AlertBanner>
            )}
          </div>
        }
      />

      {/* Reflects the sections actually selected, not a fixed list: a card
          promising an SBOM summary above a report that excludes it is the
          same dishonesty the document's own section manifest exists to
          prevent, one screen earlier. */}
      <WhatsIncludedCard
        items={
          sectionCatalog.length === 0
            ? FALLBACK_INCLUDED
            : chosenSections.length > 0
              ? chosenSections.map((s) => s.description)
              : ["Nothing yet, choose at least one section above."]
        }
        footnote={
          excludedSections.length > 0
            ? `Excluded from this report: ${excludedSections
                .map((s) => s.label)
                .join(", ")}. Excluded sections are named on the document itself, and the filters above are printed on it too, so a narrowed export can never be mistaken for a full one. All figures reflect each target's default branch, matching the Posture Dashboard.`
            : "All figures reflect each target's default branch, matching the Posture Dashboard. The filters you chose are printed on the document itself."
        }
      />
    </div>
  );
}
