import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import { Badge, Card, ErrorBox, Spinner, formatBytes, formatDate } from "../components/ui.jsx";

const STATUS_STYLE = {
  done: "bg-emerald-100 text-emerald-800 ring-emerald-600/20",
  failed: "bg-red-100 text-red-800 ring-red-600/20",
  running: "bg-blue-100 text-blue-800 ring-blue-600/20",
  queued: "bg-slate-100 text-slate-700 ring-slate-500/20",
};
const GRADE_STYLE = { A: "text-green-600", B: "text-lime-600", C: "text-yellow-600", D: "text-orange-600", F: "text-red-600" };

export default function HistoryPage() {
  const [scans, setScans] = useState(null);
  const [error, setError] = useState("");
  const [deleting, setDeleting] = useState(null);

  const load = useCallback(() => {
    setError("");
    api.listScans().then((r) => setScans(r.scans)).catch((e) => setError(e.message));
  }, []);
  useEffect(() => { load(); }, [load]);

  async function remove(scan) {
    if (!window.confirm(`Delete the scan of ${scan.file_name} and all its files? This cannot be undone.`)) return;
    setDeleting(scan.id);
    try {
      await api.deleteScan(scan.id);
      setScans((s) => s.filter((x) => x.id !== scan.id));
    } catch (e) {
      setError(e.message);
    } finally {
      setDeleting(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Scan history</h1>
          <p className="text-sm text-slate-500">Every APK you analyzed, newest first.</p>
        </div>
        <button onClick={load} className="rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-semibold hover:bg-slate-50">Refresh</button>
      </div>
      <ErrorBox message={error} onRetry={load} />
      <Card>
        {!scans ? (
          <div className="flex justify-center py-10"><Spinner className="h-7 w-7" /></div>
        ) : scans.length === 0 ? (
          <div className="py-10 text-center text-sm text-slate-500">
            No scans yet. <Link to="/" className="font-medium text-emerald-700 hover:underline">Analyze your first APK</Link>.
          </div>
        ) : (
          <div className="-mx-4 overflow-x-auto sm:-mx-5">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="px-5 py-2 font-medium">App</th>
                  <th className="px-5 py-2 font-medium">Grade</th>
                  <th className="px-5 py-2 font-medium">Findings</th>
                  <th className="px-5 py-2 font-medium">Status</th>
                  <th className="hidden px-5 py-2 font-medium md:table-cell">Scanned</th>
                  <th className="px-5 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {scans.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-50">
                    <td className="max-w-xs px-5 py-3">
                      <Link to={`/scans/${s.id}`} className="block truncate font-medium text-slate-900 hover:text-emerald-700">
                        {s.app_name || s.file_name}
                      </Link>
                      <span className="block truncate font-mono text-xs text-slate-400">
                        {s.package_name || s.file_name} - {formatBytes(s.size_bytes)}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      {s.grade ? (
                        <span className={`text-lg font-bold ${GRADE_STYLE[s.grade]}`}>{s.grade}<span className="ml-1 text-xs font-normal text-slate-400">{s.risk_score}</span></span>
                      ) : "-"}
                    </td>
                    <td className="px-5 py-3 tabular-nums">{s.finding_count ?? "-"}</td>
                    <td className="px-5 py-3">
                      <Badge className={STATUS_STYLE[s.status]}>{s.status}</Badge>
                      {s.status === "failed" && s.error && <span className="mt-1 block max-w-[16rem] truncate text-xs text-red-600" title={s.error}>{s.error}</span>}
                    </td>
                    <td className="hidden px-5 py-3 text-slate-500 md:table-cell">{formatDate(s.created_at)}</td>
                    <td className="px-5 py-3 text-right">
                      <div className="flex justify-end gap-2">
                        {s.status === "done" && (
                          <a href={api.reportUrl(s.id)} className="rounded-lg px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-100">PDF</a>
                        )}
                        <button onClick={() => remove(s)} disabled={deleting === s.id || ["queued", "running"].includes(s.status)}
                                className="rounded-lg px-2 py-1 text-xs font-semibold text-red-600 hover:bg-red-50 disabled:opacity-40">
                          {deleting === s.id ? "Deleting..." : "Delete"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
