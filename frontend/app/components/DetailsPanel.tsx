"use client";
import { useEffect, useState, type ReactNode } from "react";
import type { ApiRemediation, ApiValidation } from "../lib/types";
import { ApiError, requestRemediation, validateFinding } from "../lib/api";
import { Basis, Finding, epssText, expressionConfirmed, fileReadConfirmed, fmtScore, kevText, missingName } from "../findings";

// Small colored label showing where a value came from
function BasisTag({ basis }: { basis: Basis }) {
  const styles: Record<Basis, string> = {
    declared: "bg-sky-900/60 text-sky-300",
    scenario: "bg-amber-900/60 text-amber-300",
    verified: "bg-emerald-900/60 text-emerald-300",
  };
  const labels: Record<Basis, string> = {
    declared: "Declared context",
    scenario: "Demo assumption",
    verified: "Verified",
  };
  return (
    <span className={`text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded ${styles[basis]}`}>
      {labels[basis]}
    </span>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-t border-slate-800 pt-5 mt-5">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">{title}</h3>
      {children}
    </section>
  );
}

function errorMessage(e: unknown): string {
  if (e instanceof ApiError && e.code === "VALIDATION_RUNNING") return "A validation is already running. Try again in a moment.";
  return e instanceof Error ? e.message : "Unknown error";
}

// Render whatever the backend puts in remediation sections/sources without assuming a shape
const asText = (x: unknown): string =>
  typeof x === "string" ? x : x && typeof x === "object" && "label" in x ? String((x as { label: unknown }).label) : JSON.stringify(x);

function sourceLink(x: unknown): ReactNode {
  if (!x || typeof x !== "object" || !("url" in x)) return asText(x);
  const source = x as { url?: unknown; label?: unknown };
  if (typeof source.url !== "string") return asText(x);
  try {
    const url = new URL(source.url);
    if (url.protocol !== "https:" || !["httpd.apache.org", "cwiki.apache.org", "struts.apache.org"].includes(url.hostname))
      return asText(x);
    return <a href={url.href} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline">{asText(x)}</a>;
  } catch {
    return asText(x);
  }
}

export default function DetailsPanel({
  finding,
  mock,
  onClose,
  onValidated,
}: {
  finding: Finding;
  mock: boolean;
  onClose: () => void;
  onValidated: (id: string, v: ApiValidation) => void;
}) {
  const [open, setOpen] = useState<string | null>("threat");
  const [validating, setValidating] = useState(false);
  const [valError, setValError] = useState<string | null>(null);
  const [remediation, setRemediation] = useState<ApiRemediation | null>(null);
  const [remLoading, setRemLoading] = useState(false);
  const [remError, setRemError] = useState<string | null>(null);

  // (State resets per finding because page.tsx renders this with key={finding.id})

  // Close with the Escape key
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function runValidation() {
    setValidating(true);
    setValError(null);
    try {
      onValidated(finding.id, await validateFinding(finding.id, mock));
    } catch (e) {
      setValError(errorMessage(e));
    } finally {
      setValidating(false);
    }
  }

  async function loadRemediation() {
    setRemLoading(true);
    setRemError(null);
    try {
      setRemediation(await requestRemediation(finding.id, mock));
    } catch (e) {
      setRemError(errorMessage(e));
    } finally {
      setRemLoading(false);
    }
  }

  const v = finding.validation;
  const fileRead = fileReadConfirmed(v);
  const expression = expressionConfirmed(v);
  const hasRun = v.status !== "not_run";

  let resultTitle = "Not run yet";
  let resultTone = "border-slate-700 bg-slate-800/40 text-slate-200";
  if (fileRead || expression) {
    resultTitle = fileRead ? "✓ File read confirmed" : "✓ Expression evaluation confirmed";
    resultTone = "border-emerald-700 bg-emerald-950/40 text-emerald-300";
  } else if (v.status === "matched") {
    resultTitle = "Inconclusive: match reported without the expected evidence";
    resultTone = "border-amber-700 bg-amber-950/30 text-amber-300";
  } else if (hasRun) {
    resultTitle = "Inconclusive";
    resultTone = "border-amber-700 bg-amber-950/30 text-amber-300";
  }

  return (
    <>
      {/* Dark overlay behind the panel; clicking it closes the panel */}
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />

      <aside className="fixed right-0 top-0 h-full w-full max-w-xl bg-slate-900 border-l border-slate-800 z-50 overflow-y-auto p-8">
        <button
          onClick={onClose}
          className="absolute top-6 right-6 text-slate-400 hover:text-white text-2xl leading-none"
          aria-label="Close details"
        >
          ×
        </button>

        {/* ── Header ── */}
        <p className="text-xs text-slate-500">
          {finding.cve ?? "No CVE"} · {finding.sourceLabel}
          {mock && <span className="ml-2 text-red-300">MOCK DATA</span>}
        </p>
        <h2 className="text-2xl font-bold mt-1 pr-8">{finding.title}</h2>
        <p className="text-slate-400 mt-1">
          {finding.asset.name} · {finding.asset.businessService}
        </p>

        <div className="mt-6 grid grid-cols-2 gap-3">
          <div className="bg-slate-800/60 rounded-lg p-4">
            <p className="text-xs text-slate-400">CTEM priority</p>
            {finding.priority === null ? (
              <p className="text-xl font-bold text-slate-400 mt-1">Not scored</p>
            ) : (
              <p className="text-3xl font-bold">
                {fmtScore(finding.priority)}
                <span className="text-base text-slate-500 font-normal"> /100</span>
              </p>
            )}
          </div>
          <div className="bg-slate-800/60 rounded-lg p-4">
            <p className="text-xs text-slate-400">CVSS severity</p>
            <p className="text-3xl font-bold">
              {finding.cvss}
              <span className="text-base text-slate-500 font-normal"> /10</span>
            </p>
          </div>
        </div>
        <p className="text-sm text-slate-300 mt-4">{finding.summaryLine}</p>

        {/* ── Why this score ── */}
        <Section title="Why this score?">
          {finding.priority === null ? (
            <div className="rounded-lg border border-slate-700 bg-slate-800/40 p-4 text-sm">
              <p className="text-slate-200">This finding is not scored yet.</p>
              <p className="text-slate-400 mt-1">
                Missing inputs: {finding.missingInputs.map(missingName).join(", ")}. A score appears once real
                enrichment is available.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {finding.categories.map((c) => {
                const isOpen = open === c.key;
                return (
                  <div key={c.key} className="bg-slate-800/40 rounded-lg">
                    <button
                      onClick={() => setOpen(isOpen ? null : c.key)}
                      className="w-full text-left p-3"
                      aria-expanded={isOpen}
                    >
                      <div className="flex justify-between text-sm">
                        <span className="font-medium">
                          {isOpen ? "▾" : "▸"} {c.name}
                        </span>
                        <span className="font-mono">
                          {fmtScore(c.points)} / {c.max}
                        </span>
                      </div>
                      <div className="h-1.5 bg-slate-700 rounded mt-2">
                        <div
                          className="h-1.5 bg-blue-500 rounded"
                          style={{ width: `${Math.min(100, (c.points / c.max) * 100)}%` }}
                        />
                      </div>
                    </button>
                    {isOpen && (
                      <ul className="px-3 pb-3 space-y-3">
                        {c.factors.map((f) => (
                          <li key={f.label} className="text-sm">
                            <div className="flex items-center justify-between gap-3">
                              <span className="text-slate-200">{f.label}</span>
                              <span className="flex items-center gap-2 shrink-0">
                                <BasisTag basis={f.basis} />
                                <span className="font-mono w-10 text-right">+{fmtScore(f.points)}</span>
                              </span>
                            </div>
                            <p className="text-xs text-slate-500 mt-0.5">{f.explanation}</p>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                );
              })}
            </div>
          )}
          <p className="text-xs text-slate-500 mt-3">
            Scoring model {finding.modelVersion}: custom prototype weighting, not a calibrated risk model.
          </p>
        </Section>

        {/* ── Threat intelligence ── */}
        <Section title="Threat intelligence">
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <dt className="text-slate-400">CISA KEV</dt>
              <dd>{kevText(finding)}</dd>
            </div>
            <div>
              <dt className="text-slate-400">EPSS</dt>
              <dd>{epssText(finding)}</dd>
            </div>
          </dl>
          {finding.threat.basis !== "verified" && (
            <p className="text-xs text-slate-500 mt-2">Not retrieved from FIRST EPSS or CISA KEV yet.</p>
          )}
        </Section>

        {/* ── Validation ── */}
        <Section title="Exposure validation">
          {!finding.validationSupported ? (
            <p className="text-sm text-slate-400">No approved validator for this finding.</p>
          ) : (
            <>
              <button
                onClick={runValidation}
                disabled={validating}
                className="px-4 py-2 rounded-lg font-medium bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50"
              >
                {validating ? "Validating… (up to 30s)" : hasRun ? "Re-run validation" : "Validate exposure"}
              </button>

              {valError && (
                <div className="mt-4 rounded-lg border border-red-800 bg-red-950/50 p-4 text-sm">
                  <p className="font-semibold text-red-300">Validation request failed</p>
                  <p className="text-red-200 mt-1">{valError}</p>
                </div>
              )}

              <div className={`mt-4 rounded-lg border p-4 text-sm ${resultTone}`}>
                <p className="text-lg font-bold">
                  {resultTitle}
                  {v.provenance === "mock" && hasRun && <span className="ml-2 text-xs text-red-300">(MOCK)</span>}
                </p>
                <p className="text-slate-300 mt-1">{v.summary}</p>

                {hasRun && (
                  <dl className="mt-3 space-y-2 text-slate-200">
                    <div>
                      <dt className="text-slate-400">Observed at</dt>
                      <dd>{v.observed_at ? new Date(v.observed_at).toLocaleString() : "—"}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-400">Where</dt>
                      <dd>{v.viewpoint ?? "—"}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-400">Approved template</dt>
                      <dd className="font-mono text-xs">{v.template_id ?? "—"}</dd>
                    </div>
                    {v.evidence.length > 0 && (
                      <div>
                        <dt className="text-slate-400">Evidence</dt>
                        <dd>
                          <ul className="mt-1 space-y-1">
                            {v.evidence.map((e, i) => (
                              <li key={i} className="flex gap-2">
                                <span className="text-slate-400 shrink-0">{e.label}:</span>
                                <span className="font-mono text-xs break-all">{e.detail}</span>
                              </li>
                            ))}
                          </ul>
                        </dd>
                      </div>
                    )}
                    {v.limitations.length > 0 && (
                      <div>
                        <dt className="text-slate-400">Limitations</dt>
                        <dd>
                          <ul className="list-disc ml-5 mt-1">
                            {v.limitations.map((l, i) => (
                              <li key={i}>{l}</li>
                            ))}
                          </ul>
                        </dd>
                      </div>
                    )}
                  </dl>
                )}
              </div>

              <p className="text-xs text-slate-500 mt-3">
                Validation runs one approved check against the controlled local Docker lab. The Struts check evaluates
                fixed arithmetic without an operating-system command. These checks do not prove internet exposure or
                change the priority score.
              </p>
            </>
          )}
        </Section>

        {/* ── Remediation ── */}
        <Section title="Remediation guidance">
          {!remediation ? (
            <>
              <button
                onClick={loadRemediation}
                disabled={remLoading}
                className="px-4 py-2 rounded-lg font-medium bg-slate-700 hover:bg-slate-600 disabled:opacity-50"
              >
                {remLoading ? "Requesting…" : "Get remediation guidance"}
              </button>
              {remError && <p className="text-sm text-red-300 mt-3">{remError}</p>}
            </>
          ) : (
            <div className="space-y-3 text-sm">
              {remediation.status === "manual_review_required" ? (
                <p className="text-amber-300 font-semibold">Manual review required</p>
              ) : (
                <p className="text-slate-300">Status: {remediation.status}</p>
              )}
              {Object.entries(remediation.sections)
                .filter(([, items]) => items.length > 0)
                .map(([name, items]) => (
                  <div key={name}>
                    <p className="text-slate-400 capitalize">{name}</p>
                    <ul className="list-disc ml-5">
                      {items.map((x, i) => (
                        <li key={i}>{asText(x)}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              {remediation.sources.length > 0 && (
                <div>
                  <p className="text-slate-400">Sources</p>
                  <ul className="list-disc ml-5">
                    {remediation.sources.map((s, i) => (
                      <li key={i}>{sourceLink(s)}</li>
                    ))}
                  </ul>
                </div>
              )}
              {remediation.limitations.length > 0 && (
                <ul className="text-xs text-slate-400 list-disc ml-5">
                  {remediation.limitations.map((l, i) => (
                    <li key={i}>{l}</li>
                  ))}
                </ul>
              )}
              <p className="text-xs text-slate-500">
                Provenance: {remediation.provenance}
                {remediation.generated_at ? ` · ${new Date(remediation.generated_at).toLocaleString()}` : ""}
              </p>
            </div>
          )}
        </Section>
      </aside>
    </>
  );
}
