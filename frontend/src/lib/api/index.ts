/**
 * API client module providing domain-specific methods, tree-shakable exports,
 * and a backward-compatible monolithic `api` facade.
 */

export * from "./client";
export * from "./auth";
export * from "./targets";
export * from "./findings";
export * from "./scans";
export * from "./dashboard";
export * from "./security";
export * from "./admin";

// Re-export all types so existing `@/lib/api` imports continue to resolve cleanly
export * from "@/types";

import * as auth from "./auth";
import * as targets from "./targets";
import * as findings from "./findings";
import * as scans from "./scans";
import * as dashboard from "./dashboard";
import * as security from "./security";
import * as admin from "./admin";

/**
 * Backward-compatible facade aggregating all domain API endpoints into a single namespace.
 * Allows existing call sites to continue working without refactoring.
 */
export const api = {
  // Auth
  login: auth.login,
  logout: auth.logout,
  me: auth.me,
  updateMe: auth.updateMe,
  changePassword: auth.changePassword,
  notificationPreferences: auth.notificationPreferences,
  setNotificationPreferences: auth.setNotificationPreferences,

  // Targets & Groups
  targets: targets.targets,
  target: targets.target,
  createTarget: targets.createTarget,
  updateTarget: targets.updateTarget,
  targetsSummary: targets.targetsSummary,
  targetGroups: targets.targetGroups,
  assignTargetGroup: targets.assignTargetGroup,
  removeTargetGroup: targets.removeTargetGroup,
  groups: targets.groups,
  createGroup: targets.createGroup,
  updateGroup: targets.updateGroup,
  deleteGroup: targets.deleteGroup,
  pipelineWorkflow: targets.pipelineWorkflow,
  integratePipeline: targets.integratePipeline,
  bulkPipelineIntegrate: targets.bulkPipelineIntegrate,
  getPipelineIntegrationBatch: targets.getPipelineIntegrationBatch,
  massPipelineRollout: targets.massPipelineRollout,
  pipelineTemplates: targets.pipelineTemplates,
  createPipelineTemplate: targets.createPipelineTemplate,
  updatePipelineTemplate: targets.updatePipelineTemplate,
  deletePipelineTemplate: targets.deletePipelineTemplate,

  // Findings & SLA
  findings: findings.findings,
  triage: findings.triage,
  bulkTriage: findings.bulkTriage,
  findingTools: findings.findingTools,
  findingEnrichment: findings.findingEnrichment,
  slaRules: findings.slaRules,
  createSlaRule: findings.createSlaRule,
  updateSlaRule: findings.updateSlaRule,
  deleteSlaRule: findings.deleteSlaRule,
  slaCompliance: findings.slaCompliance,

  // Scans & PR Guardrail
  runScan: scans.runScan,
  getScan: scans.getScan,
  scanSummary: scans.scanSummary,
  activeScans: scans.activeScans,
  activePrScans: scans.activePrScans,
  scanHistory: scans.scanHistory,
  toolsHealth: scans.toolsHealth,
  toolsRegistry: scans.toolsRegistry,
  installTool: scans.installTool,
  getToolInstall: scans.getToolInstall,
  activeToolInstalls: scans.activeToolInstalls,
  toolAssignments: scans.toolAssignments,
  saveToolAssignment: scans.saveToolAssignment,
  runPrGuardrailScan: scans.runPrGuardrailScan,
  getPrGuardrailLog: scans.getPrGuardrailLog,
  getPrGuardrailOrgLog: scans.getPrGuardrailOrgLog,
  overridePrGuardrail: scans.overridePrGuardrail,
  getPrGuardrailFindings: scans.getPrGuardrailFindings,
  requestIgnoreFinding: scans.requestIgnoreFinding,
  getPendingIgnoreRequests: scans.getPendingIgnoreRequests,
  approveIgnore: scans.approveIgnore,
  rejectIgnore: scans.rejectIgnore,

  // Dashboard
  summary: dashboard.summary,
  stats: dashboard.stats,
  securityScore: dashboard.securityScore,
  dashboardWidgets: dashboard.dashboardWidgets,
  dashboardLayout: dashboard.dashboardLayout,
  saveDashboardLayout: dashboard.saveDashboardLayout,
  dashboardWidgetData: dashboard.dashboardWidgetData,
  posture: dashboard.posture,

  // Security & SBOM
  aibom: security.aibom,
  getDiscoveredEndpoints: security.getDiscoveredEndpoints,
  runDiscovery: security.runDiscovery,
  getDiscoveryRun: security.getDiscoveryRun,
  runApiScan: security.runApiScan,
  getLatestApiScan: security.getLatestApiScan,
  getSbom: security.getSbom,
  generateSbom: security.generateSbom,
  getSbomRun: security.getSbomRun,
  malwareCheck: security.malwareCheck,
  importGithubSbom: security.importGithubSbom,
  uploadSbom: security.uploadSbom,
  exportSbom: security.exportSbom,
  getOrgSbom: security.getOrgSbom,
  exportOrgSbom: security.exportOrgSbom,
  exportPostureReport: security.exportPostureReport,
  aiStatus: security.aiStatus,
  analyzeFinding: security.analyzeFinding,
  aiRecentAnalyses: security.aiRecentAnalyses,
  listPolicies: security.listPolicies,
  createPolicy: security.createPolicy,
  deletePolicy: security.deletePolicy,
  fpRules: security.fpRules,
  fpRuleStats: security.fpRuleStats,
  setFpRuleActive: security.setFpRuleActive,
  widenFpRule: security.widenFpRule,
  deleteFpRule: security.deleteFpRule,

  // Admin & Config
  buildInfo: admin.buildInfo,
  users: admin.users,
  createUser: admin.createUser,
  updateUserRole: admin.updateUserRole,
  deleteUser: admin.deleteUser,
  workspaces: admin.workspaces,
  updateWorkspace: admin.updateWorkspace,
  workspaceApiKey: admin.workspaceApiKey,
  regenerateWorkspaceApiKey: admin.regenerateWorkspaceApiKey,
  workspaceMemberships: admin.workspaceMemberships,
  assignWorkspaceRole: admin.assignWorkspaceRole,
  removeWorkspaceMembership: admin.removeWorkspaceMembership,
  apiTokens: admin.apiTokens,
  createApiToken: admin.createApiToken,
  revokeApiToken: admin.revokeApiToken,
  getConfig: admin.getConfig,
  updateConfig: admin.updateConfig,
  reseedEncryptionKey: admin.reseedEncryptionKey,
  testSlack: admin.testSlack,
  testJira: admin.testJira,
  testSiem: admin.testSiem,
  getGithubToken: admin.getGithubToken,
  saveGithubToken: admin.saveGithubToken,
  deleteGithubToken: admin.deleteGithubToken,
  testGithubToken: admin.testGithubToken,
  githubAppStatus: admin.githubAppStatus,
  githubAppManifestData: admin.githubAppManifestData,
  githubAppSync: admin.githubAppSync,
  updateWebhookSecret: admin.updateWebhookSecret,
  auditLog: admin.auditLog,
  auditActors: admin.auditActors,
  activity: admin.activity,
  orgActivity: admin.orgActivity,
  prs: admin.prs,
  search: admin.search,
};
