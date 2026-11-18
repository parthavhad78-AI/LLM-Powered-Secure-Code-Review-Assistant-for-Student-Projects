export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export type ConfidenceLevel = 'High' | 'Medium' | 'Low';

export type DetectionSource = 'confirmed_tool' | 'pattern_based' | 'dependency_advisory';

export type RemediationStatus =
  | 'open'
  | 'in_review'
  | 'approved'
  | 'remediated'
  | 'accepted_risk'
  | 'false_positive';

export type ScanStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled';

export type ScannerExecutionStatus =
  | 'completed'
  | 'failed'
  | 'unavailable'
  | 'timed_out'
  | 'cancelled';

export type FalsePositiveAssessment =
  | 'likely_genuine'
  | 'potential_false_positive'
  | 'requires_manual_verification';

export type ValidationStatus =
  | 'pending'
  | 'validated'
  | 'partially_validated'
  | 'not_resolved'
  | 'new_issues_detected'
  | 'validation_unavailable';

export interface StudentUser {
  id: string;
  fullName: string;
  email: string;
  preferredModel: string;
  createdAt: string;
}

export interface Project {
  id: string;
  userId: string;
  name: string;
  description: string;
  primaryLanguage: string | null;
  languages: string[];
  fileCount: number;
  totalBytes: number;
  importMethod?: 'upload' | 'zip' | 'github';
  githubRepoUrl?: string | null;
  githubOwner?: string | null;
  githubRepo?: string | null;
  githubBranch?: string | null;
  githubCommitSha?: string | null;
  githubIsPrivate?: boolean;
  lastImportedAt?: string | null;
  createdAt: string;
  updatedAt: string;
  lastScanAt?: string | null;
  openFindingsCount?: number;
}

export interface ProjectFile {
  id: string;
  projectId: string;
  relativePath: string;
  language: string;
  sizeBytes: number;
  sha256: string;
  isSupported: boolean;
  createdAt: string;
}

export interface ScannerHealth {
  name: 'custom' | 'bandit' | 'semgrep' | 'gitleaks' | 'eslint' | 'osv';
  displayName: string;
  description: string;
  supportedLanguages: string[];
  available: boolean;
  version: string | null;
  executablePath: string;
  installInstructionsWindows: string;
  installInstructionsLinux: string;
  checkedAt: string;
  error?: string | null;
}

export interface ScannerResultRecord {
  id: string;
  scanId: string;
  scannerName: string;
  available: boolean;
  version: string | null;
  status: ScannerExecutionStatus;
  durationMs: number;
  findingsCount: number;
  errorMessage: string | null;
  installHint: string | null;
  executedAt: string;
}

export interface DiagnosticScannerMessage {
  scannerName: string;
  message: string;
  line: number;
  column: number | null;
}

export interface ScanDiagnostic {
  id: string;
  scanId: string;
  projectId: string;
  canonicalKey?: string;
  scannerName: string;
  contributingScanners?: string[];
  scannerMessages?: DiagnosticScannerMessage[];
  filePath: string;
  line: number;
  column: number | null;
  severity: 'error' | 'warning';
  kind: 'syntax_error' | 'parse_warning';
  message: string;
  createdAt: string;
}

export interface ScanSession {
  id: string;
  projectId: string;
  projectName?: string;
  userId: string;
  status: ScanStatus;
  triggerType: 'manual' | 'revalidation';
  scannersRequested: string[];
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  repoUrl?: string | null;
  repoBranch?: string | null;
  commitSha?: string | null;
  startedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
  scannerResults?: ScannerResultRecord[];
  diagnostics?: ScanDiagnostic[];
}

export interface ContributingScannerEvidence {
  scannerName: string;
  ruleId: string;
  detectionSource: DetectionSource;
  title: string;
  description: string;
  severity: Severity;
  confidence: ConfidenceLevel;
  startLine: number;
  endLine: number;
  startCol: number | null;
  endCol: number | null;
  redactedEvidence: string | null;
}

export interface FindingGuidance {
  whyVulnerable: string;
  potentialImpact: string;
  recommendedApproach: string;
}

export interface SourceContextLine {
  lineNumber: number;
  text: string;
  isTarget: boolean;
  highlightStartCol: number | null;
  highlightEndCol: number | null;
}

export interface SourceContext {
  available: boolean;
  fromSnapshot: boolean;
  snapshotNotice: string | null;
  filePath: string;
  language: string;
  startLine: number;
  endLine: number;
  startCol: number | null;
  endCol: number | null;
  contextStartLine: number;
  contextEndLine: number;
  totalLines: number;
  lines: SourceContextLine[];
}

export interface Finding {
  id: string;
  scanId: string;
  projectId: string;
  projectName?: string;
  userId: string;
  fingerprint: string;
  canonicalKey?: string;
  scannerName: string;
  detectionSource: DetectionSource;
  ruleId: string;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  confidence: ConfidenceLevel;
  cweId: string | null;
  owaspCategory: string | null;
  filePath: string;
  startLine: number;
  endLine: number;
  startCol?: number | null;
  endCol?: number | null;
  language: string;
  codeSnippet: string;
  redactedEvidence: string | null;
  recommendation: string;
  references: string[];
  contributingScanners?: string[];
  scannerEvidence?: ContributingScannerEvidence[];
  guidance?: FindingGuidance;
  remediationStatus: RemediationStatus;
  detectedAt: string;
}

export interface AIAnalysis {
  id: string;
  findingId: string;
  userId: string;
  modelName: string;
  vulnerabilityMeaning: string;
  whyUnsafe: string;
  exploitationScenario: string;
  realWorldImpact: string;
  riskContext: string;
  secureRecommendation: string;
  cweOwaspContext: string;
  correctedCodeExample: string;
  falsePositiveAssessment: FalsePositiveAssessment;
  falsePositiveReasoning: string;
  uncertaintyNote: string;
  createdAt: string;
}

export interface AIConversation {
  id: string;
  userId: string;
  projectId: string | null;
  projectName?: string | null;
  title: string;
  createdAt: string;
  updatedAt: string;
}

export interface AIMessage {
  id: string;
  conversationId: string;
  role: 'user' | 'assistant';
  content: string;
  modelName: string | null;
  createdAt: string;
}

export interface RemediationProposal {
  id: string;
  findingId: string;
  projectId: string;
  userId: string;
  filePath: string;
  originalCode: string;
  proposedCode: string;
  diffSummary: string;
  explanation: string;
  status: 'pending' | 'approved' | 'rejected' | 'applied';
  validationStatus: ValidationStatus;
  validationSummary: string | null;
  backupPath: string | null;
  createdAt: string;
  reviewedAt: string | null;
  validatedAt: string | null;
}

export interface RemediationHistoryEntry {
  id: string;
  remediationId: string;
  findingId: string;
  userId: string;
  action: 'generated' | 'approved' | 'rejected' | 'applied' | 'validated' | 'restored';
  details: Record<string, unknown>;
  createdAt: string;
}

export interface ReportRecord {
  id: string;
  userId: string;
  projectId: string;
  projectName?: string;
  scanId: string | null;
  title: string;
  format: 'pdf' | 'csv';
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
    remediated: number;
  };
  createdAt: string;
}

export interface DashboardStats {
  totalProjects: number;
  totalScans: number;
  totalVulnerabilities: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  remediatedFindings: number;
  findingsByCategory: Array<{ category: string; count: number }>;
  scanActivity: Array<{ date: string; scans: number; findings: number }>;
  recentScans: ScanSession[];
}

export interface LearningTopic {
  slug: string;
  title: string;
  cweId: string;
  owaspCategory: string;
  summary: string;
  explanation: string;
  realWorldImpact: string;
  vulnerableLanguage: string;
  vulnerableCode: string;
  secureCode: string;
  preventionMethods: string[];
  relatedCategories: string[];
  quiz: Array<{
    id: string;
    question: string;
    options: string[];
    correctIndex: number;
    explanation: string;
  }>;
}

export interface LearningProgressRecord {
  topicSlug: string;
  quizScore: number;
  quizTotal: number;
  completed: boolean;
  updatedAt: string;
}

export interface GitHubStatus {
  publicImportEnabled: boolean;
  oauthConfigured: boolean;
  connected: boolean;
  username: string | null;
  scopes: string | null;
  callbackUrl: string | null;
}

export interface GitHubRepoValidation {
  url: string;
  owner: string;
  repo: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  selectedBranch: string;
  commitSha: string;
  branches: string[];
}

export interface GitHubRefreshResult {
  changed: boolean;
  previousCommitSha: string | null;
  latestCommitSha: string;
  branch: string;
  importedCount: number;
  project: Project;
}

