"use client";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import type { ApiRemediation } from "./lib/types";
import { API_BASE, ApiError, USE_MOCKS_DEFAULT, fetchFindings, requestRemediation, validateFinding } from "./lib/api";
import { Finding, fmtScore, rankByCtem, rankByCvss, toUiFinding, validationConfirmed } from "./findings";
import Reactor, { CATEGORY_COLORS } from "./components/Reactor";
import RankShift from "./components/RankShift";
import Queue from "./components/Queue";
import Readout from "./components/Readout";
import Breakdown from "./components/Breakdown";
import EventLog, { type LogEntry } from "./components/EventLog";
import ReviewToast from "./components/ReviewToast";
import AssetPanel from "./components/AssetPanel";

type SortBy = "cvss" | "ctem";
type Stage = "scope" | "discover" | "prioritize" | "validate" | "mobilize";
const STEPS: { key: Stage; label: string; hint: string }[] = [
  { key: "scope", label: "Scope", hint: "Show the asset context: what this organization cares about" },
  { key: "discover", label: "Discover", hint: "Show findings ranked by CVSS (the raw scanner view)" },
  { key: "prioritize", label: "Prioritize", hint: "Rank by CTEM and show the #1 finding's score" },
  { key: "validate", label: "Validate", hint: "Go to the approved validation check (you start it yourself)" },
  { key: "mobilize", label: "Mobilize", hint: "Go to remediation guidance (you request it yourself)" },
];

// Our own smooth scroll (the browser's built-in one can get cancelled by a click).
// Stops early if the user scrolls with the wheel/touch/keys.
let scrollAnim = 0;
function glideTo(top: number, ms = 550) {
  cancelAnimationFrame(scrollAnim);
  const maxY = document.documentElement.scrollHeight - window.innerHeight;
  const to = Math.max(0, Math.min(maxY, top));
  const from = window.scrollY;
  if (Math.abs(to - from) < 2) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    window.scrollTo(0, to);
    return;
  }
  let stopped = false;
  const stop = () => { stopped = true; };
  window.addEventListener("wheel", stop, { passive: true, once: true });
  window.addEventListener("touchstart", stop, { passive: true, once: true });
  window.addEventListener("keydown", stop, { once: true });
  const start = performance.now();
  const ease = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const step = (now: number) => {
    if (stopped) return;
    const t = Math.min(1, (now - start) / ms);
    window.scrollTo(0, from + (to - from) * ease(t));
    if (t < 1) scrollAnim = requestAnimationFrame(step);
    else {
      window.removeEventListener("wheel", stop);
      window.removeEventListener("touchstart", stop);
      window.removeEventListener("keydown", stop);
    }
  };
  scrollAnim = requestAnimationFrame(step);
}

function errText(e: unknown): string {
  if (e instanceof ApiError && e.code === "VALIDATION_RUNNING") return "A validation is already running. Try again in a moment.";
  return e instanceof Error ? e.message : "Unknown error";
}

export default function Home() {
  const [mock, setMock] = useState(USE_MOCKS_DEFAULT);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [generatedAt, setGeneratedAt] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<SortBy>("cvss");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [validatingId, setValidatingId] = useState<string | null>(null);
  const [valError, setValError] = useState<Record<string, string>>({});
  const [remediation, setRemediation] = useState<Record<string, ApiRemediation>>({});
  const [remLoadingId, setRemLoadingId] = useState<string | null>(null);
  const [remError, setRemError] = useState<Record<string, string>>({});
  const [toast, setToast] = useState<{ id: string; title: string; message: string; n: number } | null>(null);

  const [log, setLog] = useState<LogEntry[]>([]);
  const logId = useRef(0);
  const addLog = useCallback((kind: LogEntry["kind"], text: string, at?: string) => {
    logId.current += 1;
    const entry: LogEntry = { id: logId.current, at: at ?? new Date().toISOString(), kind, text };
    setLog((l) => [...l.slice(-49), entry]);
  }, []);

  const [stage, setStage] = useState<Stage>("scope");
  const [showAssets, setShowAssets] = useState(false);
  // First-run guide: the furthest stage reached so far (in order). Ends after Mobilize.
  const [maxReached, setMaxReached] = useState(0);
  const scopeShown = useRef(false);
  const queueRef = useRef<HTMLElement>(null);
  const reactorRef = useRef<HTMLElement>(null);
  const valRef = useRef<HTMLDivElement>(null);
  const remRef = useRef<HTMLDivElement>(null);
  const valBtnRef = useRef<HTMLButtonElement>(null);
  const remBtnRef = useRef<HTMLButtonElement>(null);
  const reactorVizRef = useRef<HTMLDivElement>(null);

  // Smoothly bring the radar (reactor) into view if it isn't fully visible.
  // Returns where the page will end up, or null if no scroll was needed.
  const showReactor = useCallback((): number | null => {
    const el = reactorVizRef.current;
    if (!el) return null;
    const r = el.getBoundingClientRect();
    if (r.top >= 0 && r.bottom <= window.innerHeight) return null;
    const maxY = document.documentElement.scrollHeight - window.innerHeight;
    const target = Math.max(0, Math.min(maxY, window.scrollY + r.top - 16));
    glideTo(target);
    return target;
  }, []);

  // Clicking a different finding in the queue brings the radar into view
  const selectFromQueue = (id: string, shownId: string) => {
    const changed = id !== shownId;
    setSelectedId(id);
    if (changed) setTimeout(showReactor, 60);
  };

  useEffect(() => {
    const idx = STEPS.findIndex((x) => x.key === stage);
    setMaxReached((m) => Math.max(m, idx));
  }, [stage]);
  const guideKey: Stage | null = maxReached < STEPS.length - 1 ? STEPS[maxReached + 1].key : null;

  // ── Spotlight state ──
  const [spotOn, setSpotOn] = useState(false);
  const spotEl = useRef<HTMLElement | null>(null);
  const spotTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  function clearSpot() {
    setSpotOn(false); // background fades back in
    const el = spotEl.current;
    if (!el) return;
    el.classList.add("spot-leaving"); // halo + moving glow fade out together
    // remove the lift only after the fade has fully finished
    setTimeout(() => {
      if (spotEl.current === el) {
        el.classList.remove("spotlight", "spotlight-btn", "pop", "spot-leaving");
        spotEl.current = null;
      }
    }, 950);
  }
  // Any click, key press or scroll ends the spotlight early
  useEffect(() => {
    if (!spotOn) return;
    const end = () => {
      if (spotTimer.current) clearTimeout(spotTimer.current);
      clearSpot();
    };
    window.addEventListener("pointerdown", end);
    window.addEventListener("keydown", end);
    window.addEventListener("wheel", end, { passive: true });
    return () => {
      window.removeEventListener("pointerdown", end);
      window.removeEventListener("keydown", end);
      window.removeEventListener("wheel", end);
    };
  }, [spotOn]);

  // Scroll a section into view (only if needed) and spotlight it
  const flash = useCallback((el: HTMLElement | null, variant: "section" | "button" = "section") => {
    if (!el) return;
    // Keep the page where it is unless the target is actually out of view.
    const r = el.getBoundingClientRect();
    const vh = window.innerHeight;
    const margin = 16;
    const big = r.height > vh * 0.6; // tall panels: seeing their top is enough
    // Buttons (Validate / Remediation) should sit comfortably in the upper-middle of the
    // screen, not hug the bottom edge, so their results have room to appear below.
    const comfy = variant === "button" ? r.top >= vh * 0.18 && r.top <= vh * 0.5 : true;
    const visible = (big ? r.top >= 0 && r.top < vh * 0.5 : r.top >= 0 && r.bottom <= vh) && comfy;
    if (!visible) {
      // tall panels: bring the top just into view; small targets: place them comfortably in the upper half
      const dy = big ? r.top - margin : r.top - vh * 0.35;
      glideTo(window.scrollY + dy);
    }
    // Spotlight: the target stays bright, everything else dims
    spotEl.current?.classList.remove("spotlight", "spotlight-btn", "pop", "spot-leaving");
    spotEl.current = el;
    el.classList.remove("pop", "spot-leaving");
    void el.offsetWidth; // restart the pop animation
    el.classList.add("spotlight", "pop");
    if (variant === "button") el.classList.add("spotlight-btn");
    setSpotOn(true);
    if (spotTimer.current) clearTimeout(spotTimer.current);
    spotTimer.current = setTimeout(clearSpot, 2800);
  }, []);
  const flashLater = useCallback(
    (get: () => HTMLElement | null, variant: "section" | "button" = "section") => setTimeout(() => flash(get(), variant), 80),
    [flash],
  );

  // Only the most recent load may update the screen (avoids duplicate/stale results)
  const loadSeq = useRef(0);
  const load = useCallback(
    async (useMock: boolean) => {
      const seq = ++loadSeq.current;
      setLoadError(null);
      setFindings(null);
      try {
        const data = await fetchFindings(useMock);
        if (seq !== loadSeq.current) return;
        const list = data.findings.map(toUiFinding);
        setFindings(list);
        setGeneratedAt(data.generated_at);
        // Scope comes first: show the asset context the first time data arrives
        if (!scopeShown.current) {
          scopeShown.current = true;
          setStage("scope");
          setShowAssets(true);
        }
        const model = list[0]?.modelVersion ?? "unknown model";
        addLog("info", `FINDINGS LOADED · ${list.length} findings · ${model}${useMock ? " · MOCK DATA" : ""}`, data.generated_at);
      } catch (e) {
        if (seq !== loadSeq.current) return;
        setLoadError(errText(e));
        addLog("error", `LOAD FAILED · ${errText(e)}`);
      }
    },
    [addLog],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => void load(mock), 0);
    return () => window.clearTimeout(timer);
  }, [mock, load]);

  // ── Actions ──
  async function runValidation(f: Finding) {
    setStage("validate");
    const returnTo = window.scrollY; // where the results/evidence are
    const radarAt = showReactor(); // watch the radar sweep while it runs
    const started = Date.now();
    setValidatingId(f.id);
    setValError((m) => ({ ...m, [f.id]: "" }));
    addLog("info", `VALIDATION STARTED · ${f.id}`);
    try {
      const v = await validateFinding(f.id, mock);
      setFindings((list) => list && list.map((x) => (x.id === f.id ? { ...x, validation: v } : x)));
      if (validationConfirmed(v)) {
        const proof = v.evidence.find((e) => e.label === "Controlled marker" || e.label === "Computed response header");
        addLog("ok", `VALIDATION MATCHED · ${f.id} · ${proof ? `${proof.label.toLowerCase()} ${proof.detail}` : ""}${v.provenance === "mock" ? " · MOCK" : ""}`, v.observed_at ?? undefined);
      } else {
        addLog("warn", `VALIDATION INCONCLUSIVE · ${f.id} · ${v.summary}`, v.observed_at ?? undefined);
      }
    } catch (e) {
      setValError((m) => ({ ...m, [f.id]: errText(e) }));
      addLog("error", `VALIDATION REQUEST FAILED · ${f.id} · ${errText(e)}`);
    } finally {
      setValidatingId(null);
      if (radarAt !== null) {
        // keep the radar on screen at least ~1.4s, then glide back to the results
        const wait = Math.max(0, 1400 - (Date.now() - started));
        setTimeout(() => {
          // don't fight the user: only return if they haven't scrolled elsewhere
          if (Math.abs(window.scrollY - radarAt) < 60) glideTo(returnTo, 650);
        }, wait);
      }
    }
  }

  async function runRemediation(f: Finding) {
    setStage("mobilize");
    setRemLoadingId(f.id);
    setRemError((m) => ({ ...m, [f.id]: "" }));
    addLog("info", `REMEDIATION REQUESTED · ${f.id}`);
    try {
      const r = await requestRemediation(f.id, mock);
      setRemediation((m) => ({ ...m, [f.id]: r }));
      if (r.status === "manual_review_required") {
        const message = r.limitations[0] ?? "No recommendation was generated.";
        addLog("warn", `MANUAL REVIEW REQUIRED · ${f.id} · ${message}`);
        setToast({ id: f.id, title: f.title, message, n: Date.now() });
      } else {
        addLog("ok", `REMEDIATION RECEIVED · ${f.id} · ${r.status}`);
      }
    } catch (e) {
      setRemError((m) => ({ ...m, [f.id]: errText(e) }));
      addLog("error", `REMEDIATION REQUEST FAILED · ${f.id} · ${errText(e)}`);
    } finally {
      setRemLoadingId(null);
    }
  }

  const reviewIds = Object.values(remediation)
    .filter((r) => r.status === "manual_review_required")
    .map((r) => r.finding_id);

  const openReview = useCallback(
    (id: string) => {
      setSelectedId(id);
      setToast(null);
      setStage("mobilize");
      flashLater(() => remRef.current);
    },
    [flashLater],
  );

  // Ranking buttons light Discover / Prioritize
  const chooseSort = (s: SortBy) => {
    setSortBy(s);
    setStage(s === "cvss" ? "discover" : "prioritize");
  };

  // Stage buttons take you to the matching part of the dashboard (they never start a check)
  const goToStage = (key: Stage) => {
    setStage(key);
    if (!findings) return;
    if (key === "scope") {
      setShowAssets(true);
    } else if (key === "discover") {
      setSortBy("cvss");
      flashLater(() => queueRef.current);
    } else if (key === "prioritize") {
      setSortBy("ctem");
      const top = rankByCtem(findings).find((f) => f.priority !== null);
      if (top) setSelectedId(top.id);
      flashLater(() => reactorRef.current);
    } else if (key === "validate") {
      // Keep the finding you're viewing if it has a check; otherwise the top CTEM finding that does
      const current = findings.find((f) => f.id === selectedId);
      const target =
        current && current.validationSupported ? current : rankByCtem(findings).find((f) => f.validationSupported);
      if (target) setSelectedId(target.id);
      flashLater(() => valBtnRef.current ?? valRef.current, "button");
    } else if (key === "mobilize") {
      setTimeout(() => {
        const btn = remBtnRef.current;
        flash(btn ?? remRef.current, btn ? "button" : "section");
      }, 80);
    }
  };
  const dismissToast = useCallback(() => setToast(null), []);

  // ── Header pieces (shown in every state) ──
  const header = (
    <header className="flex items-center gap-4 border-b pb-3 relative z-[35]" style={{ borderColor: "var(--line)" }}>
      <div className="hud text-[22px]" style={{ letterSpacing: ".18em", color: "var(--ink)" }}>
        CTEM <span style={{ color: "var(--cyan)" }}>//</span> Exposure Command
      </div>
      <nav className="flex gap-1.5 ml-4" aria-label="CTEM lifecycle">
        {STEPS.map(({ key, label, hint }) => {
          const on = key === stage;
          return (
            <button
              key={key}
              onClick={() => goToStage(key)}
              title={hint}
              aria-current={on ? "step" : undefined}
              className={`step hud text-[13px] px-3.5 py-1.5 border transition-all duration-500 ${key === guideKey && !on ? "guide-next" : ""}`}
              style={
                on
                  ? { color: "#001018", background: "var(--cyan)", borderColor: "var(--cyan)", boxShadow: "0 0 18px #3fd0ff88" }
                  : { color: "var(--ink2)", borderColor: "var(--line2)", background: "transparent" }
              }
            >
              {label}
            </button>
          );
        })}
      </nav>
      <div className="ml-auto flex items-center gap-2.5 text-xs">
        <span className="px-2.5 py-1.5 rounded border" style={{ borderColor: "var(--line2)", color: "var(--ink2)" }}>DEMO SCENARIO</span>
        {mock ? (
          <span className="px-2.5 py-1.5 rounded border" style={{ color: "var(--crit)", borderColor: "#7a2430", background: "#2a0b10" }}>
            MOCK DATA · NOT FROM BACKEND
          </span>
        ) : (
          <span className="px-2.5 py-1.5 rounded border" style={{ color: "var(--ok)", borderColor: "#1f6b52", background: "#0b241c" }}>
            <span className="blink">● </span>LIVE BACKEND{generatedAt ? ` · ${new Date(generatedAt).toLocaleTimeString()}` : ""}
          </span>
        )}
        {reviewIds.length > 0 && (
          <button
            onClick={() => openReview(reviewIds[0])}
            className="pulse-warn px-2.5 py-1.5 rounded font-bold"
            style={{ background: "var(--warn)", color: "#1a1000", boxShadow: "0 0 16px #ffb02088" }}
          >
            ⚠ REVIEW {reviewIds.length}
          </button>
        )}
      </div>
    </header>
  );

  const shell = (children: ReactNode) => (
    <main className="min-h-screen p-4">
      <div className="frame min-h-[calc(100vh-2rem)] rounded-2xl border p-4 flex flex-col gap-4" style={{ borderColor: "var(--line)" }}>
        {header}
        {children}
      </div>
    </main>
  );

  if (loadError) {
    return shell(
      <div className="panel p-5 max-w-xl" style={{ borderColor: "#7a2430" }}>
        <p className="hud" style={{ color: "var(--crit)" }}>Couldn&apos;t load findings</p>
        <p className="text-sm mt-1" style={{ color: "#ffb3bb" }}>{loadError}</p>
        <div className="mt-4 flex gap-2">
          <button onClick={() => load(mock)} className="hud text-xs px-3 py-1.5 rounded border" style={{ borderColor: "var(--line2)" }}>Retry</button>
          {!mock && (
            <button onClick={() => setMock(true)} className="hud text-xs px-3 py-1.5 rounded" style={{ background: "var(--warn)", color: "#1a1000" }}>
              Use mock data instead
            </button>
          )}
        </div>
        <p className="text-xs mt-3" style={{ color: "var(--ink3)" }}>Backend address: {API_BASE}</p>
      </div>,
    );
  }

  if (!findings) {
    return shell(<p className="hud blink" style={{ color: "var(--ink2)" }}>Loading findings…</p>);
  }

  const byCvss = rankByCvss(findings);
  const byCtem = rankByCtem(findings);
  const cvssRank = (f: Finding) => byCvss.indexOf(f) + 1;
  const ctemRank = (f: Finding) => (f.priority === null ? null : byCtem.indexOf(f) + 1);
  const rows = sortBy === "cvss" ? byCvss : byCtem;
  const top = byCtem.find((f) => f.priority !== null) ?? byCtem[0];
  const selected = findings.find((f) => f.id === selectedId) ?? top;

  const toggleStyle = (active: boolean) =>
    active
      ? { color: "var(--cyan)", borderColor: "var(--cyan)", background: "#0a2533", boxShadow: "0 0 12px #3fd0ff44 inset" }
      : { color: "var(--ink3)", borderColor: "var(--line2)" };

  return shell(
    <>
      <div className="grid gap-4 flex-1" style={{ gridTemplateColumns: "380px minmax(420px,1fr) 440px" }}>
        {/* LEFT: queue + rank shift */}
        <section ref={queueRef} className="panel p-4 flex flex-col gap-3">
          <h3 className="hud text-xs" style={{ color: "var(--ink2)" }}>Exposure queue</h3>
          <div className="flex gap-1.5" role="group" aria-label="Ranking method">
            <button onClick={() => chooseSort("cvss")} aria-pressed={sortBy === "cvss"} className="hud flex-1 text-[13px] py-1.5 rounded border transition-all" style={toggleStyle(sortBy === "cvss")}>
              {sortBy === "cvss" && "✓ "}Rank by CVSS
            </button>
            <button onClick={() => chooseSort("ctem")} aria-pressed={sortBy === "ctem"} className="hud flex-1 text-[13px] py-1.5 rounded border transition-all" style={toggleStyle(sortBy === "ctem")}>
              {sortBy === "ctem" && "✓ "}Rank by CTEM
            </button>
          </div>
          <Queue rows={rows} sortBy={sortBy} cvssRank={cvssRank} ctemRank={ctemRank} selectedId={selected.id} onSelect={(id) => selectFromQueue(id, selected.id)} />
          {sortBy === "ctem" && top && top.priority !== null && cvssRank(top) !== 1 && (
            <div className="rise rounded border p-3 text-[12px]" style={{ borderColor: "#1f6b52", background: "#0b241c" }}>
              <span style={{ color: "var(--ok)" }}>{top.title} moved from #{cvssRank(top)} to #1.</span>
              <span className="block mt-1" style={{ color: "var(--ink2)" }}>
                CVSS {top.cvss} /10, but CTEM priority {fmtScore(top.priority)} /100 · {top.summaryLine}
              </span>
            </div>
          )}
          <div className="mt-1">
            <h3 className="hud text-xs mb-1" style={{ color: "var(--ink2)" }}>Rank shift · CVSS → CTEM</h3>
            <RankShift byCvss={byCvss} byCtem={byCtem} selectedId={selected.id} showCtem={sortBy === "ctem"} onSelect={setSelectedId} />
          </div>
        </section>

        {/* CENTER: reactor + breakdown */}
        <section ref={reactorRef} className="panel p-4 flex flex-col items-center gap-3">
          <div className="w-full flex justify-between">
            <h3 className="hud text-xs" style={{ color: "var(--ink2)" }}>Priority reactor · {selected.id}</h3>
            <span className="hud text-xs" style={{ color: "var(--ink3)" }}>{selected.modelVersion}</span>
          </div>
          <div ref={reactorVizRef}>
          <Reactor key={selected.id} finding={selected} validating={validatingId === selected.id} confirmed={validationConfirmed(selected.validation)} />
          </div>
          {selected.priority !== null && (
            <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 text-[12px]" style={{ color: "var(--ink2)" }}>
              {selected.categories.map((c) => (
                <span key={c.key}>
                  <i className="inline-block w-2.5 h-2.5 rounded-sm mr-1.5 align-[-1px]" style={{ background: CATEGORY_COLORS[c.key] }} />
                  {c.name} {fmtScore(c.points)} / {c.max}
                </span>
              ))}
            </div>
          )}
          <Breakdown key={`b-${selected.id}`} finding={selected} />
        </section>

        {/* RIGHT: readout, validation, remediation */}
        <Readout
          valRef={valRef}
          valBtnRef={valBtnRef}
          remRef={remRef}
          remBtnRef={remBtnRef}
          finding={selected}
          validating={validatingId === selected.id}
          valError={valError[selected.id] || null}
          onValidate={() => runValidation(selected)}
          remediation={remediation[selected.id]}
          remLoading={remLoadingId === selected.id}
          remError={remError[selected.id] || null}
          onRemediate={() => runRemediation(selected)}
        />
      </div>

      {/* BOTTOM: event log */}
      <section className="panel p-4">
        <div className="flex justify-between mb-1.5">
          <h3 className="hud text-xs" style={{ color: "var(--ink2)" }}>Event log</h3>
          {mock && (
            <button onClick={() => setMock(false)} className="text-[11px] underline" style={{ color: "var(--ink3)" }}>
              Switch to live backend
            </button>
          )}
        </div>
        <EventLog entries={log} />
      </section>

      {/* Dims everything except the spotlighted section. Clicks pass through. */}
      <div className={`spot-overlay ${spotOn ? "on" : ""}`} aria-hidden="true" />

      {showAssets && (
        <AssetPanel
          findings={findings}
          onClose={() => setShowAssets(false)}
          onContinue={() => {
            setShowAssets(false);
            chooseSort("cvss");
            flashLater(() => queueRef.current);
          }}
          onSelect={(id) => {
            setSelectedId(id);
            setShowAssets(false);
          }}
        />
      )}

      {toast && (
        <ReviewToast
          key={`${toast.id}-${toast.n}`}
          findingId={toast.id}
          title={toast.title}
          message={toast.message}
          onOpen={() => openReview(toast.id)}
          onDismiss={dismissToast}
        />
      )}
    </>,
  );
}
