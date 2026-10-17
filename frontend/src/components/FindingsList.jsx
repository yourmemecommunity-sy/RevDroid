import { useMemo, useState } from "react";
import { Card, SEVERITIES, SeverityBadge } from "./ui.jsx";

const SEV_DOT = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-amber-500", low: "bg-blue-500", info: "bg-slate-400" };

export default function FindingsList({ findings }) {
  const [severity, setSeverity] = useState(new Set());
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(() => new Set());

  const categories = useMemo(() => [...new Set(findings.map((f) => f.category))].sort(), [findings]);
  const counts = useMemo(() => Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length])), [findings]);

  const shown = findings.filter((f) =>
    (severity.size === 0 || severity.has(f.severity)) &&
    (category === "all" || f.category === category) &&
    (!query || `${f.title} ${f.description} ${f.id}`.toLowerCase().includes(query.toLowerCase())),
  );

  const toggleSev = (s) => setSeverity((prev) => {
    const next = new Set(prev);
    next.has(s) ? next.delete(s) : next.add(s);
    return next;
  });
  const toggleOpen = (key) => setOpen((prev) => {
    const next = new Set(prev);
    next.has(key) ? next.delete(key) : next.add(key);
    return next;
  });

  return (
    <Card title={`Findings (${shown.length}${shown.length !== findings.length ? ` of ${findings.length}` : ""})`}>
      <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.filter((s) => counts[s]).map((s) => (
            <button key={s} onClick={() => toggleSev(s)} aria-pressed={severity.has(s)}
                    className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium capitalize transition ${
                      severity.has(s) ? "border-slate-900 bg-slate-900 text-white" : "border-slate-200 bg-white text-slate-700 hover:border-slate-400"}`}>
              <span className={`h-2 w-2 rounded-full ${SEV_DOT[s]}`} />
              {s} <span className="tabular-nums opacity-70">{counts[s]}</span>
            </button>
          ))}
        </div>
        <div className="flex flex-1 gap-2 lg:justify-end">
          <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category"
                  className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm capitalize">
            <option value="all">All categories</option>
            {categories.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search findings" aria-label="Search findings"
                 className="w-full min-w-0 rounded-lg border border-slate-200 px-3 py-1.5 text-sm sm:w-56" />
        </div>
      </div>

      {shown.length === 0 ? (
        <p className="py-6 text-center text-sm text-slate-500">
          {findings.length ? "No findings match these filters." : "No issues found. Nice work."}
        </p>
      ) : (
        <ul className="divide-y divide-slate-100 rounded-xl border border-slate-200">
          {shown.map((f) => {
            const key = f.id;
            const isOpen = open.has(key);
            return (
              <li key={key}>
                <button onClick={() => toggleOpen(key)} aria-expanded={isOpen}
                        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-slate-50">
                  <SeverityBadge severity={f.severity} />
                  <span className="min-w-0 flex-1">
                    <span className="block font-medium text-slate-900">{f.title}</span>
                    <span className="mt-0.5 block text-xs text-slate-500">
                      <span className="capitalize">{f.category}</span> - {f.source}
                      {f.occurrences > 1 && ` - ${f.occurrences} occurrences`}
                      {f.cwe && ` - ${f.cwe}`}
                    </span>
                  </span>
                  <svg className={`mt-1 h-4 w-4 shrink-0 text-slate-400 transition ${isOpen ? "rotate-180" : ""}`} viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M5.2 7.2a.75.75 0 0 1 1.06 0L10 10.94l3.74-3.74a.75.75 0 1 1 1.06 1.06l-4.27 4.27a.75.75 0 0 1-1.06 0L5.2 8.26a.75.75 0 0 1 0-1.06Z" />
                  </svg>
                </button>
                {isOpen && (
                  <div className="space-y-3 bg-slate-50/60 px-4 pb-4 pt-1 text-sm">
                    <p className="text-slate-700">{f.description}</p>
                    <p className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-emerald-900">
                      <span className="font-semibold">Fix: </span>{f.recommendation}
                    </p>
                    {f.masvs && <p className="text-xs text-slate-500">OWASP {f.masvs}</p>}
                    {f.locations.length > 0 && (
                      <div className="space-y-2">
                        {f.locations.slice(0, 10).map((l, i) => (
                          <div key={i} className="overflow-hidden rounded-lg border border-slate-200 bg-white">
                            <div className="truncate border-b border-slate-100 px-3 py-1 font-mono text-[11px] text-slate-500">
                              {l.file}{l.line ? `:${l.line}` : ""}
                            </div>
                            {l.snippet && <pre className="overflow-x-auto px-3 py-2 font-mono text-xs text-slate-800">{l.snippet}</pre>}
                          </div>
                        ))}
                        {f.occurrences > 10 && <p className="text-xs text-slate-500">... and {f.occurrences - 10} more</p>}
                      </div>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
