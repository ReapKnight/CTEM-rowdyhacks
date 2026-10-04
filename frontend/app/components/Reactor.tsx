"use client";
import { useEffect, useState } from "react";
import { Finding, fmtScore, missingName } from "../findings";

// One ring per CTEM category. Colors are fixed per category (never by rank).
export const CATEGORY_COLORS: Record<string, string> = {
  threat: "var(--threat)",
  exposure: "var(--exposure)",
  business_impact: "var(--business)",
  technical_severity: "var(--technical)",
};

const RADII = [168, 136, 104, 72];
const STROKE = 20;

// Counts from 0 up to the real score, ending exactly on it
function useCountUp(target: number | null, key: string) {
  const [v, setV] = useState(0);
  useEffect(() => {
    if (target === null) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setV(target);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / 1100);
      const eased = 1 - Math.pow(1 - p, 3);
      setV(p < 1 ? target * eased : target);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, key]);
  return v;
}

export default function Reactor({
  finding,
  validating,
  confirmed,
}: {
  finding: Finding;
  validating: boolean;
  confirmed: boolean;
}) {
  // Arcs start empty, then sweep to their real share on the next frame
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setArmed(true));
    return () => cancelAnimationFrame(id);
  }, []);

  const shown = useCountUp(finding.priority, finding.id);
  const scored = finding.priority !== null;

  return (
    <div className="relative" style={{ width: 400, height: 400 }}>
      {/* Radar sweep while the validation check runs */}
      {validating && (
        <div
          className="radar absolute rounded-full pointer-events-none"
          style={{
            inset: 6,
            background: "conic-gradient(from 0deg, #3fd0ff55, transparent 22%)",
          }}
        />
      )}
      <svg viewBox="-200 -200 400 400" width={400} height={400} role="img" aria-label="CTEM priority by category">
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Outer HUD ring: turns green once the file read is confirmed */}
        <circle r={194} fill="none" stroke={confirmed ? "var(--ok)" : "var(--line)"} strokeWidth={confirmed ? 2 : 1}
          filter={confirmed ? "url(#glow)" : undefined} style={{ transition: "stroke .6s" }} />
        <circle r={184} fill="none" stroke="var(--line2)" strokeDasharray="2 9" />
        {Array.from({ length: 12 }).map((_, i) => {
          const a = (i / 12) * 2 * Math.PI;
          return <circle key={i} cx={Math.sin(a) * 184} cy={-Math.cos(a) * 184} r={2.5} fill="#9bdcf5" />;
        })}

        {RADII.map((r, i) => {
          const c = finding.categories[i];
          const C = 2 * Math.PI * r;
          const frac = c ? Math.min(1, Math.max(0, c.points / c.max)) : 0;
          return (
            <g key={r}>
              <circle r={r} fill="none" stroke="#13212c" strokeWidth={STROKE} />
              {c && (
                <circle
                  r={r}
                  fill="none"
                  stroke={CATEGORY_COLORS[c.key] ?? "var(--cyan)"}
                  strokeWidth={STROKE}
                  strokeDasharray={C}
                  strokeDashoffset={armed ? C * (1 - frac) : C}
                  transform="rotate(-90)"
                  filter="url(#glow)"
                  style={{ transition: `stroke-dashoffset 1.1s cubic-bezier(.2,.8,.2,1) ${i * 0.15}s` }}
                >
                  <title>{`${c.name}: ${fmtScore(c.points)} / ${c.max}`}</title>
                </circle>
              )}
              {c && (
                <text x={-12} y={-r + 4} fill="var(--ink)" fontSize={11} textAnchor="end" style={{ fontFamily: "var(--mono)" }}>
                  {`${c.name.split(" ")[0].toUpperCase()} ${fmtScore(c.points)}/${c.max}`}
                </text>
              )}
            </g>
          );
        })}

        <circle r={52} fill="#08121a" stroke="var(--line2)" />
        <text y={-24} fill="var(--ink3)" fontSize={9} textAnchor="middle" letterSpacing={2} style={{ fontFamily: "var(--mono)" }}>
          PRIORITY
        </text>
        <text y={10} fill="var(--ink)" fontSize={scored ? 32 : 26} textAnchor="middle" filter="url(#glow)" style={{ fontFamily: "var(--mono)" }}>
          {scored ? fmtScore(Math.round(shown * 10) / 10) : "—"}
        </text>
        <text y={28} fill="var(--ink2)" fontSize={9} textAnchor="middle" letterSpacing={2} style={{ fontFamily: "var(--mono)" }}>
          {scored ? "CTEM / 100" : "NOT SCORED"}
        </text>
      </svg>

      {!scored && (
        <p className="absolute left-0 right-0 text-center text-xs" style={{ bottom: -6, color: "var(--ink3)" }}>
          Missing: {finding.missingInputs.map(missingName).join(", ")}
        </p>
      )}
    </div>
  );
}
