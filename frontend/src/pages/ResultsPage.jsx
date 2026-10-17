import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api.js";
import Endpoints from "../components/Endpoints.jsx";
import FindingsList from "../components/FindingsList.jsx";
import PermissionsTable from "../components/PermissionsTable.jsx";
import RiskGauge from "../components/RiskGauge.jsx";
import { Card, ErrorBox, ProgressBar, SEVERITIES, SeverityBadge, Spinner, formatBytes } from "../components/ui.jsx";

function Row({ label, value, mono }) {
  return (
    <div className="flex flex-col gap-0.5 py-2 sm:flex-row sm:gap-4">
      <dt className="w-36 shrink-0 text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className={`min-w-0 break-all text-sm text-slate-900 ${mono ? "font-mono text-xs" : ""}`}>{value ?? "-"}</dd>
    </div>
  );
}

export default function ResultsPage() {
  const { id } = useParams();
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const s = await api.getScan(id);
      setStatus(s);
      if (s.status === "done") setResult(await api.getResult(id));
      else if (s.status === "failed") setError(s.error || "The scan failed.");
    } catch (e) {
      setError(e.message);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  // still running (e.g. opened from history): keep polling
  useEffect(() => {
    if (!status || !["queued", "running"].includes(status.status)) return;
    const t = setTimeout(load, 1500);
    return () => clearTimeout(t);
  }, [status, load]);

  if (error) return <div className="mx-auto max-w-2xl space-y-4"><ErrorBox message={error} onRetry={load} /><Link to="/" className="text-sm text-emerald-700 hover:underline">Analyze another APK</Link></div>;
  if (!result) {
    return (
      <div className="mx-auto max-w-xl space-y-4 py-16 text-center">
        <Spinner className="mx-auto h-8 w-8" />
        <p className="text-slate-600">{status?.stage || "Loading results..."}</p>
        {status && <ProgressBar value={status.progress || 0} />}
      </div>
    );
  }

  const { identity: app, risk, file } = result;
  const cert = app.signing.certificates[0];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0 max-w-full">
          <p className="text-sm text-slate-500">Analysis report</p>
          <h1 className="truncate text-2xl font-bold tracking-tight sm:text-3xl">{app.app_name || app.package_name}</h1>
          <p className="truncate font-mono text-sm text-slate-500">{app.package_name}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link to="/" className="rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-semibold hover:bg-slate-50">New scan</Link>
          <a href={api.reportUrl(id)} download
             className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-4 py-2 text-sm font-semibold text-white shadow hover:bg-slate-800">
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path strokeLinecap="round" strokeLinejoin="round" d="M12 4v12m0 0 4-4m-4 4-4-4M4 20h16" /></svg>
            Download PDF
          </a>
        </div>
      </div>

      {result.warnings?.length > 0 && (
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          <p className="font-medium">Analysis notes</p>
          <ul className="mt-1 list-disc pl-5">{result.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Risk score" className="lg:col-span-1">
          <RiskGauge score={risk.score} grade={risk.grade} />
          <div className="mt-4 grid grid-cols-5 gap-1 text-center">
            {SEVERITIES.map((s) => (
              <div key={s} className="rounded-lg bg-slate-50 py-2">
                <p className="text-lg font-bold tabular-nums">{risk.severity_counts[s]}</p>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">{s}</p>
              </div>
            ))}
          </div>
          <details className="mt-4 text-sm">
            <summary className="cursor-pointer font-medium text-slate-700">How is this calculated?</summary>
            <p className="mt-2 text-slate-600">{risk.explanation}</p>
            <table className="mt-3 w-full text-xs">
              <thead><tr className="text-left text-slate-500"><th className="py-1">Category</th><th>Points</th><th>Cap</th></tr></thead>
              <tbody>
                {risk.breakdown.map((b) => (
                  <tr key={b.category} className="border-t border-slate-100">
                    <td className="py-1 capitalize">{b.category}</td>
                    <td className="tabular-nums">{b.points}{b.raw_points > b.points && <span className="text-slate-400"> ({b.raw_points})</span>}</td>
                    <td className="tabular-nums text-slate-500">{b.cap}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </Card>

        <Card title="App info" className="lg:col-span-2">
          <dl className="divide-y divide-slate-100">
            <Row label="Version" value={`${app.version_name ?? "-"} (code ${app.version_code ?? "-"})`} />
            <Row label="SDK" value={`min ${app.min_sdk ?? "?"} - target ${app.target_sdk ?? "?"}`} />
            <Row label="Main activity" value={app.main_activity} mono />
            <Row label="Signing" value={["v1", "v2", "v3"].filter((v) => app.signing[v]).join(", ") || "unsigned"} />
            {cert && <Row label="Signer" value={cert.subject} />}
            {cert && <Row label="Cert SHA-256" value={cert.sha256} mono />}
            <Row label="File" value={`${file.file_name} - ${formatBytes(file.size_bytes)}`} />
            <Row label="SHA-256" value={file.sha256} mono />
            <Row label="MD5" value={file.md5} mono />
            <Row label="Analysis" value={`${result.stats.java_files} classes decompiled, ${result.stats.files_scanned} files scanned in ${result.stats.total_seconds}s`} />
          </dl>
        </Card>
      </div>

      {risk.severity_counts.critical + risk.severity_counts.high > 0 && (
        <Card title="Fix these first">
          <ul className="space-y-2">
            {result.findings.filter((f) => ["critical", "high"].includes(f.severity)).slice(0, 5).map((f) => (
              <li key={f.id} className="flex items-start gap-3 text-sm">
                <SeverityBadge severity={f.severity} />
                <span><span className="font-medium">{f.title}.</span> <span className="text-slate-600">{f.recommendation}</span></span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <FindingsList findings={result.findings} />
      <div className="grid gap-6 xl:grid-cols-2">
        <PermissionsTable permissions={result.permissions} />
        <Endpoints endpoints={result.endpoints} />
      </div>
    </div>
  );
}
