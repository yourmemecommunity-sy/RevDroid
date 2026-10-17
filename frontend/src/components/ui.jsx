// Small shared UI pieces.
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const SEV_STYLES = {
  critical: "bg-red-100 text-red-800 ring-red-600/20",
  high: "bg-orange-100 text-orange-800 ring-orange-600/20",
  medium: "bg-amber-100 text-amber-800 ring-amber-600/20",
  low: "bg-blue-100 text-blue-800 ring-blue-600/20",
  info: "bg-slate-100 text-slate-700 ring-slate-500/20",
};

const LEVEL_STYLES = {
  signature: "bg-red-100 text-red-800 ring-red-600/20",
  dangerous: "bg-orange-100 text-orange-800 ring-orange-600/20",
  custom: "bg-violet-100 text-violet-800 ring-violet-600/20",
  normal: "bg-emerald-100 text-emerald-800 ring-emerald-600/20",
};

export function Badge({ children, className = "" }) {
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold capitalize ring-1 ring-inset ${className}`}>
      {children}
    </span>
  );
}

export const SeverityBadge = ({ severity }) => (
  <Badge className={`w-[4.5rem] shrink-0 justify-center ${SEV_STYLES[severity]}`}>{severity}</Badge>
);
export const LevelBadge = ({ level }) => <Badge className={LEVEL_STYLES[level]}>{level}</Badge>;

export function Card({ title, actions, children, className = "" }) {
  return (
    <section className={`min-w-0 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5 ${className}`}>
      {(title || actions) && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          {title && <h2 className="text-base font-semibold text-slate-900">{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function ErrorBox({ message, onRetry }) {
  if (!message) return null;
  return (
    <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800" role="alert">
      <p className="font-medium">Something went wrong</p>
      <p className="mt-1 break-words">{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="mt-3 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-700">
          Try again
        </button>
      )}
    </div>
  );
}

export function Spinner({ className = "h-5 w-5" }) {
  return (
    <svg className={`animate-spin text-emerald-500 ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" className="opacity-25" />
      <path d="M22 12a10 10 0 0 0-10-10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function ProgressBar({ value }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200">
      <div className="h-full rounded-full bg-emerald-500 transition-all duration-500" style={{ width: `${value}%` }} />
    </div>
  );
}

export const formatBytes = (n) =>
  n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n > 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;

export const formatDate = (iso) => (iso ? new Date(iso).toLocaleString() : "-");
