"use client";
import { useCallback, useEffect, useState } from "react";
import type { ApiValidation } from "./lib/types";
import { API_BASE, USE_MOCKS_DEFAULT, fetchFindings } from "./lib/api";
import {
  Finding,
  epssText,
  fmtScore,
  kevText,
  missingName,
  rankByCtem,
  rankByCvss,
  toUiFinding,
} from "./findings";
import DetailsPanel from "./components/DetailsPanel";

type SortBy = "cvss" | "ctem";

export default function Home() {
  const [mock, setMock] = useState(USE_MOCKS_DEFAULT);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [generatedAt, setGeneratedAt] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<SortBy>("cvss");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const load = useCallback(async (useMock: boolean) => {
    setLoadError(null);
    setFindings(null);
    try {
      const data = await fetchFindings(useMock);
      setFindings(data.findings.map(toUiFinding));
      setGeneratedAt(data.generated_at);
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : "Unknown error");
    }
  }, []);

  useEffect(() => {
    load(mock);
  }, [mock, load]);

  // When validation finishes in the panel, store the result on that finding
  const onValidated = useCallback((id: string, v: ApiValidation) => {
    setFindings((list) => list && list.map((f) => (f.id === id ? { ...f, validation: v } : f)));
  }, []);

  const buttonStyle = (active: boolean) =>
    `px-4 py-2 rounded-lg font-medium border transition ${
      active
        ? "bg-blue-600 border-blue-400 text-white ring-2 ring-blue-400/50"
        : "bg-transparent border-slate-700 text-slate-400 hover:text-slate-200"
    }`;

  // ── Header (shown in every state) ──
  const header = (
    <>
      <div className="flex flex-wrap gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider bg-amber-500/15 text-amber-300 border border-amber-500/30 rounded px-2 py-1">
          Demo scenario
        </span>
        {mock ? (
          <span className="text-xs font-semibold uppercase tracking-wider bg-red-500/15 text-red-300 border border-red-500/40 rounded px-2 py-1">
            Mock data · not from backend
          </span>
        ) : (
          <span className="text-xs font-semibold uppercase tracking-wider bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 rounded px-2 py-1">
            Live backend{generatedAt ? ` · ${new Date(generatedAt).toLocaleTimeString()}` : ""}
          </span>
        )}
      </div>
      <h1 className="text-3xl font-bold mt-3">CTEM Exposure Ranking</h1>
      <p className="text-slate-400 mt-2">Which vulnerabilities actually matter to this organization?</p>
    </>
  );

  if (loadError) {
    return (
      <main className="min-h-screen bg-slate-950 text-slate-100 p-10">
        {header}
        <div className="mt-6 max-w-xl rounded-lg border border-red-800 bg-red-950/40 p-5">
          <p className="font-semibold text-red-300">Couldn&apos;t load findings</p>
          <p className="text-sm text-red-200 mt-1">{loadError}</p>
          <div className="mt-4 flex gap-2">
            <button onClick={() => load(mock)} className="px-3 py-1.5 rounded bg-slate-800 text-sm">
              Retry
            </button>
            {!mock && (
              <button onClick={() => setMock(true)} className="px-3 py-1.5 rounded bg-amber-700 text-sm">
                Use mock data instead
              </button>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-3">Backend address: {API_BASE}</p>
        </div>
      </main>
    );
  }

  if (!findings) {
    return (
      <main className="min-h-screen bg-slate-950 text-slate-100 p-10">
        {header}
        <p className="mt-6 text-slate-400">Loading findings…</p>
      </main>
    );
  }

  const byCvss = rankByCvss(findings);
  const byCtem = rankByCtem(findings);
  const cvssRank = (f: Finding) => byCvss.indexOf(f) + 1;
  const ctemRank = (f: Finding) => (f.priority === null ? null : byCtem.indexOf(f) + 1);
  const rows = sortBy === "cvss" ? byCvss : byCtem;
  const top = byCtem.find((f) => f.priority !== null);
  const selected = findings.find((f) => f.id === selectedId) ?? null;

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-10">
      {header}

      <div className="mt-6 flex flex-wrap items-center gap-2" role="group" aria-label="Ranking method">
        <button onClick={() => setSortBy("cvss")} className={buttonStyle(sortBy === "cvss")} aria-pressed={sortBy === "cvss"}>
          {sortBy === "cvss" && "✓ "}Rank by CVSS
        </button>
        <button onClick={() => setSortBy("ctem")} className={buttonStyle(sortBy === "ctem")} aria-pressed={sortBy === "ctem"}>
          {sortBy === "ctem" && "✓ "}Rank by CTEM
        </button>
        {mock && (
          <button onClick={() => setMock(false)} className="ml-auto text-xs text-slate-400 underline">
            Switch to live backend
          </button>
        )}
      </div>

      {/* Explanation banner, only after switching to CTEM */}
      {sortBy === "ctem" && top && cvssRank(top) !== 1 && (
        <div className="mt-4 rounded-lg border border-emerald-700/60 bg-emerald-950/40 p-4">
          <p className="font-semibold text-emerald-300">
            {top.title} moved from #{cvssRank(top)} to #1
          </p>
          <p className="text-sm text-slate-300 mt-1">
            CVSS {top.cvss} /10, but CTEM priority {fmtScore(top.priority as number)} /100 · {top.summaryLine}
          </p>
          <button onClick={() => setSelectedId(top.id)} className="text-sm text-emerald-300 underline mt-2">
            See why →
          </button>
        </div>
      )}

      <table className="mt-6 w-full text-left">
        <thead className="text-slate-400 text-sm">
          <tr>
            <th className="py-2 w-10">#</th>
            <th>Finding</th>
            <th>Asset</th>
            <th>Internet-facing<span className="block text-[10px] font-normal">declared</span></th>
            <th>KEV</th>
            <th>EPSS</th>
            <th>CVSS<span className="block text-[10px] font-normal">/10</span></th>
            <th>CTEM priority<span className="block text-[10px] font-normal">/100</span></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f, i) => {
            const cr = ctemRank(f);
            const moved = sortBy === "ctem" && cr !== null && cvssRank(f) !== cr;
            const movedUp = cr !== null && cvssRank(f) > cr;
            const rankLabel = sortBy === "ctem" && cr === null ? "—" : String(i + 1);
            return (
              <tr
                key={f.id}
                onClick={() => setSelectedId(f.id)}
                className={`border-t border-slate-800 cursor-pointer hover:bg-slate-900 transition-colors ${
                  moved ? (movedUp ? "bg-emerald-950/40" : "bg-slate-900/60") : ""
                }`}
              >
                <td className="py-3 font-mono">{rankLabel}</td>
                <td>
                  <div className="font-medium">{f.title}</div>
                  <div className="text-xs text-slate-500 flex items-center gap-2 mt-0.5">
                    <span>{f.cve ?? "No CVE"}</span>
                    <span
                      className={`uppercase tracking-wide text-[10px] px-1.5 py-0.5 rounded ${
                        f.isSynthetic ? "bg-amber-900/60 text-amber-300" : "bg-sky-900/60 text-sky-300"
                      }`}
                    >
                      {f.sourceLabel}
                    </span>
                  </div>
                  {moved && (
                    <div className={`text-xs mt-1 font-semibold ${movedUp ? "text-emerald-400" : "text-slate-400"}`}>
                      {movedUp ? "▲" : "▼"} Moved from #{cvssRank(f)} to #{cr}
                    </div>
                  )}
                </td>
                <td>
                  {f.asset.name} <span className="text-xs text-slate-500">({f.asset.environment})</span>
                </td>
                <td>{f.asset.internetFacing ? "Yes" : "No"}</td>
                <td className={f.threat.kev === null || f.threat.basis !== "verified" ? "text-slate-500" : ""}>
                  {kevText(f)}
                </td>
                <td className={f.threat.epss === null || f.threat.basis !== "verified" ? "text-slate-500" : ""}>
                  {epssText(f)}
                </td>
                <td className="font-mono">{f.cvss}</td>
                <td>
                  {f.priority === null ? (
                    <span className="text-xs text-slate-500">
                      Not scored
                      <span className="block">missing {f.missingInputs.map(missingName).join(", ")}</span>
                    </span>
                  ) : (
                    <span className="font-mono font-bold">{fmtScore(f.priority)}</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <p className="text-xs text-slate-500 mt-4">
        Click a row to see why it received its score. “Synthetic” values are demo inputs, not retrieved threat
        intelligence. KEV and EPSS show “Unknown” until real data is fetched.
      </p>

      {selected && (
        <DetailsPanel
          key={selected.id}
          finding={selected}
          mock={mock}
          onClose={() => setSelectedId(null)}
          onValidated={onValidated}
        />
      )}
    </main>
  );
}
