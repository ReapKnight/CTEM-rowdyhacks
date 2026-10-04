"use client";
import { useLayoutEffect, useRef } from "react";
import { Finding, fileReadConfirmed, fmtScore, missingName } from "../findings";

// Ranked list. When the order changes, rows slide from their old spot
// to their new one (FLIP technique, no extra libraries).
export default function Queue({
  rows,
  sortBy,
  cvssRank,
  ctemRank,
  selectedId,
  onSelect,
}: {
  rows: Finding[];
  sortBy: "cvss" | "ctem";
  cvssRank: (f: Finding) => number;
  ctemRank: (f: Finding) => number | null;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const els = useRef(new Map<string, HTMLButtonElement>());
  const lastTop = useRef(new Map<string, number>());
  const orderKey = rows.map((r) => r.id).join("|");

  useLayoutEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    els.current.forEach((el, id) => {
      const nowTop = el.getBoundingClientRect().top;
      const before = lastTop.current.get(id);
      if (!reduce && before !== undefined && Math.abs(before - nowTop) > 1) {
        el.animate(
          [{ transform: `translateY(${before - nowTop}px)` }, { transform: "translateY(0)" }],
          { duration: 700, easing: "cubic-bezier(.2,.8,.2,1)" },
        );
      }
      lastTop.current.set(id, nowTop);
    });
  }, [orderKey]);

  return (
    <div className="flex flex-col gap-2">
      {rows.map((f, i) => {
        const cr = ctemRank(f);
        const moved = sortBy === "ctem" && cr !== null && cvssRank(f) !== cr;
        const up = cr !== null && cvssRank(f) > cr;
        const sel = f.id === selectedId;
        const rank = sortBy === "ctem" && cr === null ? "—" : String(i + 1);
        return (
          <button
            key={f.id}
            ref={(el) => {
              if (el) els.current.set(f.id, el);
              else els.current.delete(f.id);
            }}
            onClick={() => onSelect(f.id)}
            className={`text-left grid items-center gap-2 p-3 rounded-md border transition-colors ${sel ? "glow-soft" : ""} ${moved && up ? "row-moved-up" : ""}`}
            style={{
              gridTemplateColumns: "32px 1fr 62px",
              borderColor: sel ? "var(--cyan)" : "var(--line)",
              background: sel ? "linear-gradient(90deg,#0b2a3a,#0a121a)" : "#0a121a",
              boxShadow: sel ? "0 0 18px #3fd0ff33" : undefined,
            }}
          >
            <span className="text-2xl text-center" style={{ color: sel ? "var(--cyan)" : "var(--ink2)" }}>{rank}</span>
            <span>
              <span className="block text-[13px]" style={{ color: "var(--ink)" }}>{f.title}</span>
              <span className="block text-[11px] mt-0.5" style={{ color: "var(--ink3)" }}>
                {f.asset.name} · {f.asset.environment.toLowerCase()}
                <span
                  className="ml-1.5 px-1.5 rounded text-[10px] border"
                  style={f.isSynthetic ? { color: "var(--warn)", borderColor: "#6b4a10" } : { color: "var(--cyan)", borderColor: "#1d5870" }}
                >
                  {f.sourceLabel.toUpperCase()}
                </span>
                {fileReadConfirmed(f.validation) && (
                  <span className="ml-1.5 px-1.5 rounded text-[10px] border" style={{ color: "var(--ok)", borderColor: "#1f6b52" }}>
                    ✓ FILE READ
                  </span>
                )}
              </span>
              {moved && (
                <span className="block text-[11px] mt-0.5" style={{ color: up ? "var(--ok)" : "var(--ink3)" }}>
                  {up ? "▲" : "▼"} MOVED #{cvssRank(f)} → #{cr}
                </span>
              )}
              {f.priority === null && (
                <span className="block text-[11px] mt-0.5" style={{ color: "var(--ink3)" }}>
                  NOT SCORED · missing {f.missingInputs.map(missingName).join(", ")}
                </span>
              )}
            </span>
            <span className="text-right">
              {sortBy === "cvss" ? (
                <>
                  <span className="text-xl">{f.cvss}</span>
                  <span className="block text-[10px]" style={{ color: "var(--ink3)" }}>CVSS /10</span>
                </>
              ) : (
                <>
                  <span className="text-xl" style={{ color: f.priority === null ? "var(--ink3)" : undefined }}>
                    {f.priority === null ? "—" : fmtScore(f.priority)}
                  </span>
                  <span className="block text-[10px]" style={{ color: "var(--ink3)" }}>CTEM /100</span>
                </>
              )}
            </span>
          </button>
        );
      })}
    </div>
  );
}
