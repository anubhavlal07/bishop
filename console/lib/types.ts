export type VerdictLabel =
  "true_positive" | "false_positive" | "benign_true_positive" | "escalate";

export type EvidenceKind =
  "detector" | "observation" | "intel" | "injection" | "mitigating";

export interface Health {
  status: string;
  version: string;
  provider: string;
  model: string;
  offline: boolean;
  store?: {
    connected: boolean;
    dialect?: string;
    incidents?: number;
    error?: string;
  };
  live?: LiveReadiness;
  deployment?: DeploymentInfo;
}

export interface DeploymentInfo {
  environment: "development" | "production";
  auth_required: boolean;
  api_keys_configured: number;
  cors_origins: string[];
  rate_limit_per_minute: number;
  max_request_bytes: number;
  database: string;
  json_logs: boolean;
}

export interface LiveReadiness {
  selected: string;
  package_installed: boolean;
  api_key_present: boolean;
  ready: boolean;
  missing: string[];
  what_mock_still_does: string;
}

export interface AlertSummary {
  alert_id: string;
  rule_name: string;
  source: string;
  severity: string;
  category: string;
  detected_at: string;
  host: string | null;
  user: string | null;
  expected_verdict: string;
  why: string;
  synthetic: boolean;
}

export interface DetectorSignal {
  detector: string;
  fired: boolean;
  score: number;
  rationale: string;
  mitigating: boolean;
  technique_hints: string[];
  facts: Record<string, unknown>;
}

export interface Evidence {
  evidence_id: string;
  producer: string;
  kind: EvidenceKind;
  title: string;
  detail: string;
  confidence: number;
  signals: DetectorSignal[];
  technique_ids: string[];
  facts: Record<string, unknown>;
}

export interface InvestigatorReport {
  investigator: string;
  summary: string;
  evidence: Evidence[];
  skipped: boolean;
  skip_reason: string | null;
  duration_ms: number;
  tokens_used: number;
}

export interface AttackStage {
  order: number;
  tactic: string;
  technique_id: string;
  technique_name: string;
  summary: string;
}

export interface Verdict {
  label: VerdictLabel;
  confidence: number;
  rationale: string;
  narrative: string;
  stages: AttackStage[];
  technique_ids: string[];
  assessed_severity: string;
  counter_arguments: string[];
  escalation_reason: string | null;
}

export interface BlastRadius {
  users_affected: number;
  hosts_affected: number;
  services_affected: string[];
  summary: string;
  timing_context: string;
}

export interface ResponseAction {
  action_id: string;
  action_type: string;
  target: string;
  rationale: string;
  blast_radius: BlastRadius;
  evidence_ids: string[];
  rollback: string | null;
  priority: number;
}

export interface ResponsePlan {
  actions: ResponseAction[];
  // What the model wrote. Shown, never edited.
  strategy: string;
  // Computed from `actions` by the planner, so it cannot disagree with them.
  proposes: string;
  no_action_rationale: string | null;
}

export interface HumanDecision {
  decided_by: string;
  decision: string;
  approved_action_ids: string[];
  note: string;
  decided_at: string;
}

export interface ExecutionRecord {
  action_id: string;
  action_type: string;
  target: string;
  status: "simulated" | "refused";
  detail?: string;
  reason?: string;
  approved_by?: string | null;
  irreversible?: boolean;
  at: string;
}

export interface RunCost {
  model_calls: number;
  input_tokens: number;
  output_tokens: number;
  usd: number;
  wall_ms: number;
}

export interface Incident {
  incident_id: string;
  entity_key: string;
  alerts: Array<Record<string, unknown>>;
  reports: InvestigatorReport[];
  verdict: Verdict | null;
  response_plan: ResponsePlan | null;
  human_decision: HumanDecision | null;
  execution_log: ExecutionRecord[];
  cost: RunCost | null;
  audit_head: string | null;
}

export interface ApprovalRequest {
  kind: string;
  incident_id: string;
  entity: string;
  verdict: {
    label: VerdictLabel | null;
    confidence: number | null;
    rationale: string;
    counter_arguments: string[];
    technique_ids: string[];
  };
  proposes: string;
  strategy: string;
  actions: Array<{
    action_id: string;
    action_type: string;
    target: string;
    rationale: string;
    irreversible: boolean;
    rollback: string | null;
    blast_radius: BlastRadius;
  }>;
  instructions: string;
}

export type RunStatus =
  "queued" | "running" | "awaiting_approval" | "done" | "failed";

export interface RunState {
  run_id: string;
  alert_id: string;
  status: RunStatus;
  error: string | null;
  approval_request: ApprovalRequest | null;
  incident: Incident | null;
  audit_entries: number;
  audit_intact: boolean;
}

export interface AuditEntry {
  seq: number;
  timestamp: string;
  run_id: string;
  actor: string;
  action: string;
  payload: Record<string, unknown>;
  payload_hash: string;
  prev_hash: string;
  entry_hash: string;
}

export interface CoverageEntry {
  technique_id: string;
  name: string;
  tactics: string[];
  detectors: string[];
  fixtures: string[];
  status: "covered" | "untested" | "none";
  url: string;
}

export interface Coverage {
  attack_version: string;
  summary: string;
  entries: CoverageEntry[];
}

export interface DetectorSpec {
  name: string;
  surface: string;
  summary: string;
  techniques: string[];
  references: string[];
}

export interface ScorecardOutcome {
  alert_id: string;
  expected: string;
  actual: string;
  correct: boolean;
  confidence: number;
  missed_true_positive: boolean;
  injection_expected: boolean;
  injection_caught: boolean;
  duration_ms: number;
}

export interface Scorecard {
  generated_at: string;
  provider: string;
  model: string;
  attack_version: string;
  corpus_size: number;
  corpus_is_synthetic: boolean;
  verdict_accuracy: number;
  false_negative_rate: number;
  false_positive_rate: number;
  escalation_precision: number;
  escalation_recall: number;
  benign_tp_accuracy: number;
  injection_caught: number;
  injection_total: number;
  injection_escalated_as_ioc: number;
  invalid_techniques_emitted: number;
  technique_recall: number;
  median_triage_ms: number;
  p95_triage_ms: number;
  usd_per_alert: number;
  total_model_calls: number;
  outcomes: ScorecardOutcome[];
  notes: string[];
}

export interface RunEvent {
  kind: string;
  at?: string;
  [key: string]: unknown;
}

export interface MappingReport {
  detected_format: string;
  mapped: { from: string; to: string }[];
  ignored: string[];
  defaulted: { field: string; value: string; why: string }[];
  warnings: string[];
  detectors_with_jurisdiction: string[];
}

export interface IngestPreview {
  alert: Record<string, unknown>;
  mapping: MappingReport;
  usable: boolean;
}
