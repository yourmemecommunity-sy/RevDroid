import { useEffect, useState } from "react";
import { api } from "../api.js";

// Small header pill: green when java, apktool, jadx and androguard are all ready.
export default function ToolStatus() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setError(true));
  }, []);

  if (error) return <Pill color="bg-red-500" label="Backend offline" title="Start the backend on port 8000" />;
  if (!health) return <Pill color="bg-slate-400" label="Checking tools" />;
  const missing = Object.entries(health.tools).filter(([, t]) => !t.ready).map(([n]) => n);
  const title = Object.entries(health.tools).map(([n, t]) => `${n}: ${t.ready ? t.version : "missing"}`).join("\n");
  return missing.length ? (
    <Pill color="bg-amber-400" label={`Missing: ${missing.join(", ")}`} title={title} />
  ) : (
    <Pill color="bg-emerald-400" label="All tools ready" title={title} />
  );
}

function Pill({ color, label, title }) {
  return (
    <span title={title} className="hidden items-center gap-2 rounded-full bg-white/10 px-3 py-1 text-xs text-slate-200 sm:inline-flex">
      <span className={`h-2 w-2 rounded-full ${color}`} />
      {label}
    </span>
  );
}
