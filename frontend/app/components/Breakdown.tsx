"use client";
import { useState } from "react";
import { Basis, Finding, fmtScore } from "../findings";
import { CATEGORY_COLORS } from "./Reactor";

const BASIS: Record<Basis, { label: string; color: string; border: string }> = {
  declared: { label: "DECLARED CONTEXT", color: "#7cc8e6", border: "#1d5870" },
  scenario: { label: "DEMO ASSUMPTION", color: "var(--warn)", border: "#6b4a10" },
  verified: { label: "VERIFIED", color: "var(--ok)", border: "#1f6b52" },
};

// "Why this score?" — every factor, its points, the backend's explanation, and where it came from.
export default function Breakdown({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState<string | null>("threat");
  if (finding.priority === null) return null;
  return (
    <div className="w-full flex flex-col gap-1.5">
      {finding.categories.map((c) => {
        const isOpen = open === c.key;
        const color = CATEGORY_COLORS[c.key] ?? "var(--cyan)";
        return (
          <div key={c.key} className="rounded border" style={{ borderColor: "var(--line)", background: "#0a121a" }}>
            <button onClick={() => setOpen(isOpen ? null : c.key)} className="w-full text-left px-3 py-2" aria-expanded={isOpen}>
              <div className="flex justify-between text-[13px]">
                <span>
                  <i className="inline-block w-2.5 h-2.5 rounded-sm mr-2 align-[-1px]" style={{ background: color }} />
                  {isOpen ? "▾" : "▸"} {c.name}
                </span>
                <span>{fmtScore(c.points)} / {c.max}</span>
              </div>
            </button>
            {isOpen && (
              <ul className="px-3 pb-3 flex flex-col gap-2">
                {c.factors.map((f) => (
                  <li key={f.label} className="text-[12px] rise">
                    <div className="flex justify-between gap-3">
                      <span style={{ color: "var(--ink)" }}>{f.label}</span>
                      <span className="flex items-center gap-2 shrink-0">
                        <span className="px-1.5 rounded border text-[10px]" style={{ color: BASIS[f.basis].color, borderColor: BASIS[f.basis].border }}>
                          {BASIS[f.basis].label}
                        </span>
                        <span className="w-10 text-right">+{fmtScore(f.points)}</span>
                      </span>
                    </div>
                    <p className="text-[11px] mt-0.5" style={{ color: "var(--ink3)" }}>{f.explanation}</p>
                  </li>
                ))}
              </ul>
            )}
          </div>
        );
      })}
      <p className="text-[11px] mt-1" style={{ color: "var(--ink3)" }}>
        Scoring model {finding.modelVersion}: custom prototype weighting, not a calibrated risk model.
      </p>
    </div>
  );
}
