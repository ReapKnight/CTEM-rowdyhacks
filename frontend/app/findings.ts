// ─────────────────────────────────────────────────────────────
// THE ADAPTER: turns backend responses into what the screens show.
// This is the only place that knows about backend field names.
//
// Honesty rules enforced here:
//   • A value is "verified" only when the backend gives a retrieval date.
//   • Synthetic / predefined values keep their "scenario" or "declared" label.
//   • Missing data stays missing (null → "Unknown" / "Not scored").
// ─────────────────────────────────────────────────────────────
import type { ApiFinding, ApiValidation } from "./lib/types";

// Where a value came from:
//   "declared" = predefined asset context for the demo
//   "scenario" = synthetic / not-yet-retrieved threat or severity data
//   "verified" = retrieved from a real source, with a date
export type Basis = "declared" | "scenario" | "verified";

export type Factor = {
  label: string;
  points: number;
  explanation: string;
  basis: Basis;
};

export type Category = {
  key: string;
  name: string;
  max: number;
  points: number;
  factors: Factor[];
};

export type Finding = {
  id: string;
  cve: string | null;
  title: string;
  sourceLabel: string; // "Controlled lab" | "Synthetic"
  isSynthetic: boolean;

  asset: {
    name: string;
    environment: string;
    businessService: string;
    criticality: string;
    internetFacing: boolean;
    dataSensitivity: string;
  };

  cvss: number;

  threat: {
    kev: boolean | null;
    epss: number | null; // 0–1
    epssDate: string | null;
    kevRetrievedAt: string | null;
    basis: Basis;
  };

  priority: number | null; // null = not scored
  modelVersion: string;
  categories: Category[];
  missingInputs: string[];

  summaryLine: string; // factual one-liner built from asset context
  validationSupported: boolean;
  validation: ApiValidation;
};

const CATEGORY_NAMES: Record<string, string> = {
  threat: "Threat",
  exposure: "Exposure",
  business_impact: "Business Impact",
  technical_severity: "Technical Severity",
};

const MISSING_NAMES: Record<string, string> = {
  "threat.epss_probability": "EPSS probability",
  "threat.kev": "CISA KEV status",
  "cvss.score": "CVSS score",
  "asset.internet_facing": "Internet exposure",
  "asset.data_sensitivity": "Data sensitivity",
};

export const missingName = (key: string) => MISSING_NAMES[key] ?? key;

const cap = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);

export function toUiFinding(f: ApiFinding): Finding {
  const t = f.threat;
  const threatBasis: Basis =
    t.provenance !== "synthetic_demo" && t.provenance !== "mock" && (t.epss_date || t.kev_retrieved_at)
      ? "verified"
      : "scenario";

  const basisFor = (key: string): Basis =>
    key === "threat" ? threatBasis : key === "exposure" || key === "business_impact" ? "declared" : "scenario";

  return {
    id: f.id,
    cve: f.cve_id,
    title: f.title,
    sourceLabel: f.discovery_source === "prepared_lab" ? "Controlled lab" : "Synthetic",
    isSynthetic: f.discovery_source !== "prepared_lab",
    asset: {
      name: f.asset.name,
      environment: cap(f.asset.environment),
      businessService: f.asset.business_service,
      criticality: f.asset.criticality,
      internetFacing: f.asset.internet_facing,
      dataSensitivity: f.asset.data_sensitivity,
    },
    cvss: f.cvss.score,
    threat: {
      kev: t.kev,
      epss: t.epss_probability,
      epssDate: t.epss_date,
      kevRetrievedAt: t.kev_retrieved_at,
      basis: threatBasis,
    },
    priority: f.priority.score,
    modelVersion: f.priority.model_version,
    categories: f.priority.categories.map((c) => ({
      key: c.key,
      name: CATEGORY_NAMES[c.key] ?? c.key,
      max: c.max_points,
      points: c.points,
      factors: c.factors.map((x) => ({
        label: x.label,
        points: x.points,
        explanation: x.explanation,
        basis: basisFor(c.key),
      })),
    })),
    missingInputs: f.priority.missing_inputs,
    summaryLine: `${cap(f.asset.environment)} · ${f.asset.criticality} criticality · ${
      f.asset.internet_facing ? "internet-facing" : "not internet-facing"
    } (predefined demo context)`,
    validationSupported: f.validation_supported,
    validation: f.validation,
  };
}

// ── Display helpers ──────────────────────────────────────────

export const fmtScore = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(1));

export function kevText(f: Finding): string {
  if (f.threat.kev === null) return "Unknown";
  const v = f.threat.kev ? "Listed" : "Not listed";
  if (f.threat.basis === "verified" && f.threat.kevRetrievedAt) return `${v} · retrieved ${f.threat.kevRetrievedAt.slice(0, 10)}`;
  return `${v} · synthetic`;
}

// EPSS as a percentage that never rounds up to certainty (or down to zero).
// 0.99992 → "99.992%", 0.9999996 → ">99.999%", 1 → "100%", 0.0001 → "<0.1%"
export function formatEpss(p: number): string {
  if (p >= 1) return "100%";
  if (p <= 0) return "0%";
  const pct = p * 100;
  if (pct < 0.1) return "<0.1%";
  if (pct < 99.9) return `${pct.toFixed(1)}%`;
  const precise = pct.toFixed(3);
  return precise === "100.000" ? ">99.999%" : `${Number(precise)}%`;
}

export function epssText(f: Finding): string {
  if (f.threat.epss === null) return "Unknown";
  const v = formatEpss(f.threat.epss);
  if (f.threat.basis === "verified" && f.threat.epssDate) return `${v} · ${f.threat.epssDate}`;
  return `${v} · synthetic`;
}

// Only the expected approved template and its exact evidence can confirm a result.
export function fileReadConfirmed(v: ApiValidation | null): boolean {
  return (
    !!v &&
    v.status === "matched" &&
    ((v.template_id === "ctem-cve-2021-41773-readonly" &&
      v.evidence.some((e) => e.label === "Controlled marker" && e.detail === "CTEM-LAB-PROOF-41773")) ||
      (v.template_id === "ctem-cve-2021-42013-readonly" &&
        v.evidence.some((e) => e.label === "Controlled marker" && e.detail === "CTEM-LAB-PROOF-42013"))) &&
    v.evidence.some((e) => e.label === "HTTP response" && e.detail === "200 OK")
  );
}

export function expressionConfirmed(v: ApiValidation | null): boolean {
  return (
    !!v &&
    v.status === "matched" &&
    v.template_id === "ctem-cve-2017-5638-expression" &&
    v.evidence.some((e) => e.label === "Computed response header" && e.detail === "5421")
  );
}

// ── Ranking ──────────────────────────────────────────────────

export function rankByCvss(list: Finding[]): Finding[] {
  return [...list].sort((a, b) => b.cvss - a.cvss);
}

// Scored findings first (highest first); unscored findings go last
export function rankByCtem(list: Finding[]): Finding[] {
  return [...list].sort((a, b) => {
    if (a.priority === null && b.priority === null) return b.cvss - a.cvss;
    if (a.priority === null) return 1;
    if (b.priority === null) return -1;
    return b.priority - a.priority;
  });
}

// Any approved lab check confirmed (file read for Apache, expression evaluation for Struts)
export function validationConfirmed(v: ApiValidation | null): boolean {
  return fileReadConfirmed(v) || expressionConfirmed(v);
}
