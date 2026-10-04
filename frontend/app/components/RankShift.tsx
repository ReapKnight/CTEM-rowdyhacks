"use client";
import { useEffect, useState } from "react";
import { Finding } from "../findings";

// Slope chart: each finding's CVSS rank (left) vs CTEM rank (right).
// Crossing lines = severity alone would have ranked these wrong.
export default function RankShift({
  byCvss,
  byCtem,
  selectedId,
  showCtem,
  onSelect,
}: {
  byCvss: Finding[];
  byCtem: Finding[];
  selectedId: string | null;
  showCtem: boolean;
  onSelect: (id: string) => void;
}) {
  const W = 350;
  const top = 34;
  const gap = 50;
  const xL = 40;
  const xR = 300;
  const n = byCvss.length;
  const H = top + gap * Math.max(n - 1, 0) + 30;
  const y = (rank: number) => top + gap * rank;

  // Re-draw the lines each time the CTEM view is switched on
  const [drawn, setDrawn] = useState(false);
  useEffect(() => {
    setDrawn(false);
    const id = requestAnimationFrame(() => setDrawn(true));
    return () => cancelAnimationFrame(id);
  }, [showCtem]);

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Rank shift from CVSS to CTEM">
      <text x={xL} y={14} fill="var(--ink3)" fontSize={11} textAnchor="middle">CVSS</text>
      <text x={xR} y={14} fill="var(--ink3)" fontSize={11} textAnchor="middle">CTEM</text>
      <line x1={xL} y1={top - 10} x2={xL} y2={H - 14} stroke="var(--line)" />
      <line x1={xR} y1={top - 10} x2={xR} y2={H - 14} stroke="var(--line)" />

      {byCvss.map((f, i) => {
        const j = f.priority === null ? null : byCtem.indexOf(f);
        const sel = f.id === selectedId;
        const color = sel ? "var(--cyan)" : "var(--ink3)";
        const y1 = y(i);
        const x2 = j === null ? xR - 30 : xR;
        const y2 = j === null ? y1 : y(j);
        const len = Math.hypot(x2 - xL, y2 - y1);
        return (
          <g key={f.id} onClick={() => onSelect(f.id)} style={{ cursor: "pointer" }}>
            <title>{`${f.title}: CVSS #${i + 1} → ${j === null ? "not scored" : `CTEM #${j + 1}`}`}</title>
            <line
              x1={xL} y1={y1} x2={x2} y2={y2}
              stroke={color}
              strokeWidth={sel ? 2.5 : 2}
              strokeDasharray={j === null ? "4 5" : len}
              strokeDashoffset={j === null || !showCtem ? 0 : drawn ? 0 : len}
              opacity={showCtem ? 1 : 0.35}
              style={{ transition: "stroke-dashoffset .9s cubic-bezier(.2,.8,.2,1), opacity .4s" }}
            />
            {/* bigger invisible hit target */}
            <line x1={xL} y1={y1} x2={x2} y2={y2} stroke="transparent" strokeWidth={14} />
            <circle cx={xL} cy={y1} r={sel ? 6 : 5} fill={color} stroke="var(--bg)" strokeWidth={2} />
            <text x={xL - 14} y={y1 + 4} fill={color} fontSize={11} textAnchor="end">#{i + 1}</text>
            <text x={xL + 12} y={y1 - 8} fill={color} fontSize={10} stroke="var(--panel)" strokeWidth={4} style={{ paintOrder: "stroke" }}>{`${f.asset.name} · ${f.cvss}`}</text>
            {j === null ? (
              <text x={x2 + 4} y={y2 + 4} fill="var(--ink3)" fontSize={10}>n/s</text>
            ) : (
              <>
                <circle cx={xR} cy={y2} r={sel ? 6 : 5} fill={color} stroke="var(--bg)" strokeWidth={2} opacity={showCtem ? 1 : 0.35} />
                <text x={xR + 10} y={y2 + 4} fill={color} fontSize={11} opacity={showCtem ? 1 : 0.35}>#{j + 1}</text>
              </>
            )}
          </g>
        );
      })}
    </svg>
  );
}
