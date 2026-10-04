// ─────────────────────────────────────────────────────────────
// Exact shapes returned by the backend (CTEM-rowdyhacks/backend/app).
// Keep these in sync with main.py, data.py, scoring.py, validation.py.
// The UI never reads these directly — app/findings.ts adapts them.
// ─────────────────────────────────────────────────────────────

export type ApiAsset = {
  id: string;
  name: string;
  environment: string; // "production" | "development"
  business_service: string;
  criticality: string; // "low" | "medium" | "high" | "critical"
  internet_facing: boolean;
  data_sensitivity: string; // "low" | "medium" | "high"
  context_source: string; // "predefined_demo"
};

export type ApiFactor = {
  label: string;
  points: number;
  explanation: string;
};

export type ApiCategory = {
  key: string; // "threat" | "exposure" | "business_impact" | "technical_severity"
  max_points: number;
  points: number;
  factors: ApiFactor[];
};

export type ApiPriority = {
  score: number | null; // null when required inputs are missing
  model_version: string;
  categories: ApiCategory[];
  missing_inputs: string[]; // e.g. ["threat.epss_probability", "threat.kev"]
};

export type ApiEvidence = { label: string; detail: string };

// Returned by POST /api/findings/{id}/validate, and embedded in each finding
export type ApiValidation = {
  status: string; // "not_run" | "matched" | "error"
  provenance: string; // "live" | "mock"
  observed_at: string | null;
  template_id: string | null;
  kind?: "file_read" | "expression_evaluation";
  viewpoint: string | null;
  summary: string;
  evidence: ApiEvidence[];
  limitations: string[];
};

export type ApiFinding = {
  id: string; // e.g. "lab-httpd-41773"
  cve_id: string | null;
  title: string;
  discovery_source: string; // "prepared_lab" | "synthetic_demo"
  asset: ApiAsset;
  cvss: { score: number; version: string; source: string };
  threat: {
    epss_probability: number | null;
    epss_percentile: number | null;
    kev: boolean | null;
    epss_date: string | null;
    kev_retrieved_at: string | null;
    provenance: string; // "synthetic_demo" until real enrichment exists
  };
  validation_supported: boolean;
  priority: ApiPriority;
  validation: ApiValidation;
};

// GET /api/findings
export type ApiFindingsResponse = {
  findings: ApiFinding[];
  generated_at: string;
};

// POST /api/findings/{id}/remediation
export type ApiRemediation = {
  finding_id: string;
  status: string; // "manual_review_required" | ...
  provenance: string;
  generated_at: string | null;
  sections: Record<string, unknown[]>;
  sources: unknown[];
  limitations: string[];
};

// Error body for 4xx responses
export type ApiErrorBody = {
  error: { code: string; message: string; retryable: boolean };
};
