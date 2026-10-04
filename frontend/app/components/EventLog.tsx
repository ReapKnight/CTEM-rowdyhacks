"use client";
import { useEffect, useRef } from "react";

export type LogEntry = {
  id: number;
  at: string; // ISO time the event happened
  kind: "info" | "ok" | "warn" | "error";
  text: string;
};

const COLORS: Record<LogEntry["kind"], string> = {
  info: "var(--ink2)",
  ok: "var(--ok)",
  warn: "var(--warn)",
  error: "var(--crit)",
};

// Only real events from this session — nothing pre-written.
export default function EventLog({ entries }: { entries: LogEntry[] }) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    box.current?.scrollTo({ top: box.current.scrollHeight, behavior: "smooth" });
  }, [entries.length]);

  return (
    <div ref={box} className="h-[112px] overflow-y-auto pr-2">
      {entries.length === 0 && <div className="text-[13px]" style={{ color: "var(--ink3)" }}>Waiting for events…</div>}
      {entries.map((e, i) => {
        const last = i === entries.length - 1;
        return (
          <div
            key={e.id}
            className="rise text-[13px] px-2 py-1 border-l-2"
            style={{
              color: COLORS[e.kind],
              borderColor: e.kind === "warn" ? "var(--warn)" : "transparent",
              background: e.kind === "warn" ? "#2a1d0644" : undefined,
            }}
          >
            <span className="mr-3" style={{ color: "var(--ink3)" }}>{new Date(e.at).toLocaleTimeString()}</span>
            {e.text}
            {last && <span className="blink" style={{ color: "var(--cyan)" }}>▌</span>}
          </div>
        );
      })}
    </div>
  );
}
