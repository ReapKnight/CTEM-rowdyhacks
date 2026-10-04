"use client";
import type { ReactNode, RefObject } from "react";
import type { ApiRemediation } from "../lib/types";
import { Finding, epssText, fileReadConfirmed, fmtScore, kevText } from "../findings";

function Tag({ kind, children }: { kind: "declared" | "demo" | "verified"; children: ReactNode }) {
  const s =
    kind === "declared"
      ? { color: "#7cc8e6", borderColor: "#1d5870" }
      : kind === "verified"
        ? { color: "var(--ok)", borderColor: "#1f6b52" }
        : { color: "var(--warn)", borderColor: "#6b4a10" };
  return (
    <span className="ml-1.5 px-1.5 rounded border text-[10px] tracking-wide" style={s}>
      {children}
    </span>
  );
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <>
      <dt style={{ color: "var(--cyan)" }}>{k}:</dt>
      <dd style={{ color: "var(--ink)" }}>{children}</dd>
    </>
  );
}

const asText = (x: unknown): string =>
  typeof x === "string" ? x : x && typeof x === "object" && "label" in x ? String((x as { label: unknown }).label) : JSON.stringify(x);

type Props = {
  finding: Finding;
  validating: boolean;
  valError: string | null;
  onValidate: () => void;
  remediation: ApiRemediation | undefined;
  remLoading: boolean;
  remError: string | null;
  onRemediate: () => void;
  valRef: RefObject<HTMLDivElement | null>;
  valBtnRef: RefObject<HTMLButtonElement | null>;
  remRef: RefObject<HTMLDivElement | null>;
  remBtnRef: RefObject<HTMLButtonElement | null>;
};

// Right column: data readout + validation + remediation for the selected finding.
export default function Readout({
  finding: f,
  validating,
  valError,
  onValidate,
  remediation,
  remLoading,
  remError,
  onRemediate,
  valRef,
  valBtnRef,
  remRef,
  remBtnRef,
}: Props) {
  const v = f.validation;
  const confirmed = fileReadConfirmed(v);
  const hasRun = v.status !== "not_run";

  let title = "NOT RUN YET";
  let tone = { color: "var(--ink2)", border: "var(--line2)", bg: "#0a121a" };
  if (confirmed) {
    title = "✓ FILE READ CONFIRMED";
    tone = { color: "var(--ok)", border: "#1f6b52", bg: "#0b241c" };
  } else if (v.status === "matched") {
    title = "INCONCLUSIVE · MATCH WITHOUT MARKER EVIDENCE";
    tone = { color: "var(--warn)", border: "#6b4a10", bg: "#2a1d0644" };
  } else if (hasRun) {
    title = "INCONCLUSIVE";
    tone = { color: "var(--warn)", border: "#6b4a10", bg: "#2a1d0644" };
  }

  return (
    <div
      className="panel p-4 flex flex-col gap-4"
      style={{ borderColor: confirmed ? "#1f6b52" : "#1d5870", boxShadow: confirmed ? "0 0 24px #2ee59d22 inset" : "0 0 24px #1b98c622 inset", transition: "border-color .6s, box-shadow .6s" }}
    >
      <div>
        <h3 className="hud text-xs mb-3" style={{ color: "var(--ink2)" }}>Finding readout</h3>
        <dl className="grid gap-y-2 text-[13px]" style={{ gridTemplateColumns: "150px 1fr" }}>
          <Row k="FINDING ID">{f.id}</Row>
          <Row k="TITLE">{f.title}</Row>
          <Row k="CVE">{f.cve ?? "None"}{f.isSynthetic && <Tag kind="demo">SYNTHETIC</Tag>}</Row>
          <Row k="SOURCE">{f.sourceLabel}</Row>
          <Row k="ASSET">{f.asset.name}</Row>
          <Row k="BUSINESS SERVICE">{f.asset.businessService}</Row>
          <Row k="ENVIRONMENT">{f.asset.environment.toLowerCase()}<Tag kind="declared">DECLARED</Tag></Row>
          <Row k="CRITICALITY">{f.asset.criticality}<Tag kind="declared">DECLARED</Tag></Row>
          <Row k="INTERNET-FACING">{f.asset.internetFacing ? "yes" : "no"}<Tag kind="declared">DECLARED</Tag></Row>
          <Row k="DATA SENSITIVITY">{f.asset.dataSensitivity}<Tag kind="declared">DECLARED</Tag></Row>
          <Row k="CVSS">{f.cvss} / 10<Tag kind="demo">DEMO ASSUMPTION</Tag></Row>
          <Row k="CISA KEV">{kevText(f)}</Row>
          <Row k="EPSS">{epssText(f)}</Row>
          <Row k="CTEM PRIORITY">
            <span style={{ color: f.priority === null ? "var(--ink3)" : "var(--cyan)" }}>
              {f.priority === null ? "Not scored" : `${fmtScore(f.priority)} / 100`}
            </span>
          </Row>
        </dl>
      </div>

      {/* ── Validation ── */}
      <div ref={valRef} className="border-t pt-4 scroll-mt-24 rounded" style={{ borderColor: "var(--line)" }}>
        <h3 className="hud text-xs mb-3" style={{ color: "var(--ink2)" }}>Exposure validation</h3>
        {!f.validationSupported ? (
          <p className="text-[13px]" style={{ color: "var(--ink3)" }}>No approved validator for this finding.</p>
        ) : (
          <>
            <button
              ref={valBtnRef}
              onClick={onValidate}
              disabled={validating}
              className="hud text-xs px-4 py-2 rounded border disabled:opacity-60"
              style={{ color: "#00140d", background: "var(--ok)", borderColor: "var(--ok)", boxShadow: "0 0 14px #2ee59d55" }}
            >
              {validating ? "◌ Scanning… (up to 30s)" : hasRun ? "Re-run validation" : "Validate exposure"}
            </button>
            {valError && (
              <div className="mt-3 rounded border p-3 text-[12px]" style={{ borderColor: "#7a2430", background: "#2a0b10", color: "#ffb3bb" }}>
                <b style={{ color: "var(--crit)" }}>VALIDATION REQUEST FAILED</b>
                <div className="mt-1">{valError}</div>
              </div>
            )}
            <div key={`${v.status}-${v.observed_at}`} className="mt-3 rounded border p-3" style={{ borderColor: tone.border, background: tone.bg }}>
              <div className={`hud text-[15px] ${confirmed ? "stamp" : ""}`} style={{ color: tone.color }}>
                {title}
                {hasRun && v.provenance === "mock" && <span className="ml-2 text-[11px]" style={{ color: "var(--crit)" }}>(MOCK)</span>}
              </div>
              <p className="text-[12px] mt-1" style={{ color: "var(--ink2)" }}>{v.summary}</p>
              {hasRun && (
                <dl className="mt-2 grid gap-y-1 text-[12px]" style={{ gridTemplateColumns: "110px 1fr" }}>
                  <dt style={{ color: "var(--ink3)" }}>Observed</dt>
                  <dd>{v.observed_at ? new Date(v.observed_at).toLocaleString() : "—"}</dd>
                  <dt style={{ color: "var(--ink3)" }}>Where</dt>
                  <dd>{v.viewpoint ?? "—"}</dd>
                  <dt style={{ color: "var(--ink3)" }}>Template</dt>
                  <dd className="break-all">{v.template_id ?? "—"}</dd>
                  {v.evidence.map((e, i) => (
                    <div key={i} className="contents">
                      <dt className="rise" style={{ color: "var(--ink3)", animationDelay: `${0.15 + i * 0.25}s` }}>{e.label}</dt>
                      <dd className="rise break-all" style={{ animationDelay: `${0.15 + i * 0.25}s` }}>{e.detail}</dd>
                    </div>
                  ))}
                </dl>
              )}
              {hasRun && v.limitations.length > 0 && (
                <ul className="mt-2 text-[11px] list-disc ml-4" style={{ color: "var(--ink3)" }}>
                  {v.limitations.map((l, i) => <li key={i}>{l}</li>)}
                </ul>
              )}
            </div>
            <p className="text-[11px] mt-2" style={{ color: "var(--ink3)" }}>
              One approved, read-only check against the controlled local Docker lab. Does not prove internet exposure or
              RCE, and does not change the priority score.
            </p>
          </>
        )}
      </div>

      {/* ── Remediation ── */}
      <div ref={remRef} className="border-t pt-4 scroll-mt-24 rounded" style={{ borderColor: "var(--line)" }}>
        <h3 className="hud text-xs mb-3" style={{ color: "var(--ink2)" }}>Remediation guidance</h3>
        {!remediation ? (
          <>
            <button
              ref={remBtnRef}
              onClick={onRemediate}
              disabled={remLoading}
              className="hud text-xs px-4 py-2 rounded border disabled:opacity-60"
              style={{ color: remLoading ? "var(--cyan)" : "var(--ink2)", borderColor: remLoading ? "var(--cyan)" : "var(--line2)", boxShadow: remLoading ? "0 0 14px #3fd0ff55" : undefined }}
            >
              {remLoading ? "◌ Requesting…" : "Get remediation guidance"}
            </button>
            {remError && <p className="text-[12px] mt-2" style={{ color: "var(--crit)" }}>{remError}</p>}
          </>
        ) : (
          <div className="rounded border p-3 text-[12px]" style={{ borderColor: remediation.status === "manual_review_required" ? "#6b4a10" : "var(--line2)" }}>
            {remediation.status === "manual_review_required" ? (
              <div className="hud text-[15px]" style={{ color: "var(--warn)" }}>⚠ Manual review required</div>
            ) : (
              <div style={{ color: "var(--ink2)" }}>Status: {remediation.status}</div>
            )}
            {Object.entries(remediation.sections)
              .filter(([, items]) => items.length > 0)
              .map(([name, items]) => (
                <div key={name} className="mt-2">
                  <div className="capitalize" style={{ color: "var(--ink3)" }}>{name}</div>
                  <ul className="list-disc ml-4">{items.map((x, i) => <li key={i}>{asText(x)}</li>)}</ul>
                </div>
              ))}
            {remediation.sources.length > 0 && (
              <div className="mt-2">
                <div style={{ color: "var(--ink3)" }}>Sources</div>
                <ul className="list-disc ml-4">{remediation.sources.map((s, i) => <li key={i}>{asText(s)}</li>)}</ul>
              </div>
            )}
            {remediation.limitations.length > 0 && (
              <ul className="mt-2 list-disc ml-4" style={{ color: "var(--ink2)" }}>
                {remediation.limitations.map((l, i) => <li key={i}>{l}</li>)}
              </ul>
            )}
            <div className="mt-2 text-[11px]" style={{ color: "var(--ink3)" }}>
              Provenance: {remediation.provenance}
              {remediation.generated_at ? ` · ${new Date(remediation.generated_at).toLocaleString()}` : ""}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
