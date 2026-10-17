import { useState } from "react";
import { Card, LevelBadge } from "./ui.jsx";

export default function PermissionsTable({ permissions }) {
  const [showNormal, setShowNormal] = useState(false);
  const shown = showNormal ? permissions : permissions.filter((p) => p.protection_level !== "normal");
  const hidden = permissions.length - shown.length;

  return (
    <Card
      title={`Permissions (${permissions.length})`}
      actions={
        permissions.some((p) => p.protection_level === "normal") && (
          <button onClick={() => setShowNormal((v) => !v)} className="text-sm font-medium text-emerald-700 hover:underline">
            {showNormal ? "Hide normal permissions" : `Show ${hidden} normal`}
          </button>
        )
      }
    >
      {shown.length === 0 ? (
        <p className="text-sm text-slate-500">No dangerous, signature or custom permissions requested.</p>
      ) : (
        <div className="-mx-4 overflow-x-auto sm:-mx-5">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="px-5 py-2 font-medium">Permission</th>
                <th className="px-5 py-2 font-medium">Level</th>
                <th className="px-5 py-2 font-medium">What it allows</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {shown.map((p) => (
                <tr key={p.name} className="hover:bg-slate-50">
                  <td className="px-5 py-2">
                    <span className="font-mono text-xs text-slate-900">{p.short_name}</span>
                    <span className="block font-mono text-[11px] text-slate-400">{p.name}</span>
                  </td>
                  <td className="px-5 py-2"><LevelBadge level={p.protection_level} /></td>
                  <td className="px-5 py-2 text-slate-600">
                    {p.description}
                    {p.high_impact && <span className="ml-2 text-xs font-semibold text-red-600">high impact</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
