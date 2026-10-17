import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { Card, ErrorBox, ProgressBar, Spinner, formatBytes } from "../components/ui.jsx";

const MAX_MB = 150;
const STEPS = ["Upload", "Identity", "Manifest", "Decompile", "Code scan", "Score"];

function stepIndex(phase, progress) {
  if (phase === "uploading") return 0;
  if (progress >= 92) return 5;
  if (progress >= 75) return 4;
  if (progress >= 40) return 3;
  if (progress >= 25) return 2;
  return 1;
}

export default function UploadPage() {
  const navigate = useNavigate();
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [phase, setPhase] = useState("idle"); // idle | uploading | analyzing
  const [uploadPct, setUploadPct] = useState(0);
  const [scan, setScan] = useState(null);
  const [error, setError] = useState("");
  const [consent, setConsent] = useState(false);

  // poll the scan status while the backend works
  useEffect(() => {
    if (phase !== "analyzing" || !scan?.id) return;
    const timer = setInterval(async () => {
      try {
        const s = await api.getScan(scan.id);
        setScan(s);
        if (s.status === "done") navigate(`/scans/${s.id}`);
        if (s.status === "failed") {
          setError(s.error || "Analysis failed");
          setPhase("idle");
        }
      } catch (e) {
        setError(e.message);
        setPhase("idle");
      }
    }, 1200);
    return () => clearInterval(timer);
  }, [phase, scan?.id, navigate]);

  function pick(f) {
    setError("");
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".apk")) return setError("Please choose an .apk file.");
    if (f.size > MAX_MB * 1024 * 1024) return setError(`The file is larger than ${MAX_MB} MB.`);
    if (f.size === 0) return setError("The file is empty.");
    setFile(f);
  }

  async function start() {
    if (!file) return;
    setError("");
    setPhase("uploading");
    setUploadPct(0);
    try {
      const res = await api.upload(file, setUploadPct);
      setScan({ id: res.scan_id, status: "queued", stage: "Queued", progress: 0 });
      setPhase("analyzing");
    } catch (e) {
      setError(e.message);
      setPhase("idle");
    }
  }

  const busy = phase !== "idle";
  const current = stepIndex(phase, scan?.progress ?? 0);
  const overall = phase === "uploading" ? Math.round(uploadPct * 0.1) : Math.max(10, scan?.progress ?? 10);

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div className="text-center">
        <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Take an APK apart, safely.</h1>
        <p className="mx-auto mt-3 max-w-xl text-slate-600">
          RevDroid decodes the manifest, decompiles the code, hunts for hardcoded secrets and insecure
          patterns, and gives the app an explainable risk score with a PDF report.
        </p>
      </div>

      <Card>
        <div
          role="button"
          tabIndex={0}
          aria-disabled={busy}
          onClick={() => !busy && inputRef.current?.click()}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && !busy && inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); if (!busy) setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); if (!busy) pick(e.dataTransfer.files?.[0]); }}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-14 text-center transition ${
            dragging ? "border-emerald-500 bg-emerald-50" : "border-slate-300 hover:border-slate-400 hover:bg-slate-50"
          } ${busy ? "pointer-events-none opacity-60" : ""}`}
        >
          <svg className="h-12 w-12 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 16V4m0 0-4 4m4-4 4 4M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
          </svg>
          {file ? (
            <>
              <p className="mt-4 font-semibold text-slate-900">{file.name}</p>
              <p className="text-sm text-slate-500">{formatBytes(file.size)} - click to choose another file</p>
            </>
          ) : (
            <>
              <p className="mt-4 font-semibold text-slate-900">Drop an APK here or click to browse</p>
              <p className="text-sm text-slate-500">.apk files up to {MAX_MB} MB</p>
            </>
          )}
          <input ref={inputRef} type="file" accept=".apk,application/vnd.android.package-archive" className="hidden"
                 onChange={(e) => { pick(e.target.files?.[0]); e.target.value = ""; }} />
        </div>

        {!busy && (
          <div className="mt-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <label className="flex items-start gap-2 text-sm text-slate-600">
              <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)}
                     className="mt-0.5 h-4 w-4 rounded border-slate-300 accent-emerald-600" />
              I own this app or have permission to test it.
            </label>
            <button onClick={start} disabled={!file || !consent}
                    className="rounded-xl bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white shadow hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40">
              Analyze APK
            </button>
          </div>
        )}

        {busy && (
          <div className="mt-6 space-y-4" aria-live="polite">
            <div className="flex items-center gap-3">
              <Spinner />
              <p className="text-sm font-medium text-slate-700">
                {phase === "uploading" ? `Uploading... ${uploadPct}%` : scan?.stage || "Working..."}
              </p>
              <span className="ml-auto text-sm tabular-nums text-slate-500">{overall}%</span>
            </div>
            <ProgressBar value={overall} />
            <ol className="grid grid-cols-3 gap-2 text-xs sm:grid-cols-6">
              {STEPS.map((s, i) => (
                <li key={s} className={`rounded-lg px-2 py-1.5 text-center font-medium ${
                  i < current ? "bg-emerald-50 text-emerald-700" : i === current ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-400"}`}>
                  {s}
                </li>
              ))}
            </ol>
            <p className="text-xs text-slate-500">Large apps can take a few minutes; decompiling is the slowest step.</p>
          </div>
        )}
      </Card>

      <ErrorBox message={error} />

      <div className="grid gap-4 sm:grid-cols-3">
        {[
          ["Manifest", "Permissions, exported components, debuggable, backup and cleartext flags."],
          ["Code", "Hardcoded keys, weak crypto, disabled TLS checks, risky WebViews, leaky logs."],
          ["Report", "Risk score and grade, network endpoints and a downloadable PDF."],
        ].map(([t, d]) => (
          <div key={t} className="rounded-xl border border-slate-200 bg-white p-4">
            <p className="font-semibold">{t}</p>
            <p className="mt-1 text-sm text-slate-600">{d}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
