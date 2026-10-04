"use client";
import { useEffect } from "react";
import { Finding, fmtScore } from "../findings";

// SCOPE: the organization's asset context, grouped by asset.
// Every value comes straight from the backend's asset fields (predefined demo context).
export default function AssetPanel({
  findings,
  onClose,
  onContinue,
  onSelect,
}: {
  findings: Finding[];
  onClose: () => void;
  onContinue: () => void;
  onSelect: (id: string) => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Group findings by asset name
  const assets = new Map<string, { asset: Finding["asset"]; findings: Finding[] }>();
  for (const f of findings) {
    const entry = assets.get(f.asset.name) ?? { asset: f.asset, findings: [] };
    entry.findings.push(f);
    assets.set(f.asset.name, entry);
  }

  const tag = (
    <span className="ml-1.5 px-1.5 rounded border text-[10px]" style={{ color: "#7cc8e6", borderColor: "#1d5870" }}>
      DECLARED
    </span>
  );

  return (
    <>
      <div className="fixed inset-0 z-40" style={{ background: "#000a" }} onClick={onClose} />
      <div
        role="dialog"
        aria-label="Scope: asset context"
        className="rise fixed z-50 panel p-5 overflow-y-auto"
        style={{ position: "fixed", top: 80, left: 0, right: 0, marginLeft: "auto", marginRight: "auto", width: "min(1100px, 94vw)", maxHeight: "80vh" }}
      >
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="hud text-sm" style={{ color: "var(--cyan)" }}>Scope · asset context</h2>
            <p className="text-[12px] mt-1" style={{ color: "var(--ink3)" }}>
              What this organization cares about. Predefined demo context from the backend; not discovered automatically.
            </p>
          </div>
          <button onClick={onClose} className="text-2xl leading-none px-2" style={{ color: "var(--ink2)" }} aria-label="Close scope panel">
            ×
          </button>
        </div>

        <table className="w-full text-left text-[13px]">
          <thead className="hud text-[11px]" style={{ color: "var(--ink3)" }}>
            <tr>
              <th className="py-2">Asset</th>
              <th>Business service</th>
              <th>Environment</th>
              <th>Criticality</th>
              <th>Internet-facing</th>
              <th>Data sensitivity</th>
              <th>Findings on this asset</th>
            </tr>
          </thead>
          <tbody>
            {[...assets.values()].map(({ asset, findings: fs }) => (
              <tr key={asset.name} className="border-t align-top" style={{ borderColor: "var(--line)" }}>
                <td className="py-3" style={{ color: "var(--cyan)" }}>{asset.name}</td>
                <td className="py-3">{asset.businessService}</td>
                <td className="py-3">{asset.environment.toLowerCase()}{tag}</td>
                <td className="py-3">{asset.criticality}{tag}</td>
                <td className="py-3">{asset.internetFacing ? "yes" : "no"}{tag}</td>
                <td className="py-3">{asset.dataSensitivity}{tag}</td>
                <td className="py-3">
                  {fs.map((f) => (
                    <button
                      key={f.id}
                      onClick={() => onSelect(f.id)}
                      className="block text-left underline decoration-dotted underline-offset-2 hover:text-[var(--cyan)]"
                      title="Inspect this finding"
                    >
                      {f.title} · {f.priority === null ? "not scored" : `CTEM ${fmtScore(f.priority)}`}
                    </button>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div className="flex items-center justify-between mt-5 pt-4 border-t" style={{ borderColor: "var(--line)" }}>
          <p className="text-[12px]" style={{ color: "var(--ink3)" }}>
            {assets.size} assets in scope · {findings.length} findings. Reopen this anytime from the Scope stage.
          </p>
          <button
            onClick={onContinue}
            className="glow-soft nudge hud text-xs px-4 py-2 rounded border"
            style={{ color: "var(--cyan)", borderColor: "var(--cyan)", background: "#0a2533", boxShadow: "0 0 14px #3fd0ff44" }}
            title="Close scope and show the discovered findings"
          >
            Continue to Discover →
          </button>
        </div>
      </div>
    </>
  );
}
