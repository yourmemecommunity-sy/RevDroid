import { useState } from "react";
import { Badge, Card } from "./ui.jsx";

const TABS = ["domains", "urls", "ips"];
const LABELS = { domains: "Domains", urls: "URLs", ips: "IP addresses" };

export default function Endpoints({ endpoints }) {
  const [tab, setTab] = useState("domains");
  const items = endpoints[tab] || [];

  return (
    <Card
      title="Network endpoints"
      actions={
        <div className="flex max-w-full overflow-x-auto rounded-lg bg-slate-100 p-0.5 text-xs sm:text-sm">
          {TABS.map((t) => (
            <button key={t} onClick={() => setTab(t)}
                    className={`whitespace-nowrap rounded-md px-2 py-1 font-medium sm:px-3 ${tab === t ? "bg-white shadow-sm" : "text-slate-500 hover:text-slate-800"}`}>
              {LABELS[t]} <span className="tabular-nums text-slate-400">{endpoints[t]?.length ?? 0}</span>
            </button>
          ))}
        </div>
      }
    >
      {items.length === 0 ? (
        <p className="text-sm text-slate-500">No {LABELS[tab].toLowerCase()} found in the app's own code.</p>
      ) : (
        <ul className="max-h-80 divide-y divide-slate-100 overflow-y-auto rounded-xl border border-slate-200">
          {items.map((e) => {
            const label = e.domain || e.url || e.ip;
            const insecure = tab === "domains" ? e.insecure : tab === "urls" ? ["http", "ws"].includes(e.scheme) : false;
            return (
              <li key={label} className="flex items-center gap-3 px-4 py-2 text-sm">
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-800" title={label}>{label}</span>
                {insecure && <Badge className="bg-orange-100 text-orange-800 ring-orange-600/20">plain HTTP</Badge>}
                {e.scope && <Badge className="bg-slate-100 text-slate-700 ring-slate-500/20">{e.scope}</Badge>}
                <span className="shrink-0 text-xs tabular-nums text-slate-400">{e.count}x</span>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
