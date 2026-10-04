"use client";
import { useEffect } from "react";

// Slides in when the backend says a remediation needs manual review.
// Uses the backend's own wording. Auto-hides after 10s; the header badge stays.
export default function ReviewToast({
  findingId,
  title,
  message,
  onOpen,
  onDismiss,
}: {
  findingId: string;
  title: string;
  message: string;
  onOpen: () => void;
  onDismiss: () => void;
}) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 10000);
    return () => clearTimeout(t);
  }, [findingId, onDismiss]);

  return (
    <div
      role="alert"
      className="toast fixed z-50 rounded-lg border p-4"
      style={{
        top: 88,
        right: 28,
        width: 430,
        borderColor: "var(--warn)",
        borderLeftWidth: 4,
        background: "linear-gradient(180deg,#2a1c05,#16100a)",
        boxShadow: "0 0 30px #ffb02055, 0 10px 30px #000a",
      }}
    >
      <div className="hud text-[15px]" style={{ color: "var(--warn)" }}>⚠ Remediation needs review</div>
      <div className="text-[12px] mt-1.5 leading-relaxed" style={{ color: "#f3dcb0" }}>
        {findingId} · {title}
        <br />
        {message}
      </div>
      <div className="flex gap-2 mt-3">
        <button onClick={onOpen} className="hud text-xs px-3 py-1.5 rounded" style={{ background: "var(--warn)", color: "#1a1000" }}>
          Open review
        </button>
        <button onClick={onDismiss} className="hud text-xs px-3 py-1.5 rounded border" style={{ borderColor: "#6b4a10", color: "#f3dcb0" }}>
          Dismiss
        </button>
      </div>
    </div>
  );
}
