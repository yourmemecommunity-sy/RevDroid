// Semicircle gauge: 0 (safe, green) to 100 (risky, red).
const GRADE_COLORS = { A: "#16a34a", B: "#65a30d", C: "#ca8a04", D: "#ea580c", F: "#dc2626" };

export default function RiskGauge({ score, grade }) {
  const r = 80;
  const circumference = Math.PI * r;
  const offset = circumference * (1 - Math.min(100, Math.max(0, score)) / 100);
  const color = GRADE_COLORS[grade] || "#0f172a";
  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 200 120" className="w-full max-w-[260px]" role="img" aria-label={`Risk score ${score} of 100, grade ${grade}`}>
        <defs>
          <linearGradient id="gaugeTrack" x1="0" x2="1">
            <stop offset="0%" stopColor="#bbf7d0" />
            <stop offset="50%" stopColor="#fde68a" />
            <stop offset="100%" stopColor="#fecaca" />
          </linearGradient>
        </defs>
        <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="url(#gaugeTrack)" strokeWidth="16" strokeLinecap="round" />
        <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke={color} strokeWidth="16" strokeLinecap="round"
              strokeDasharray={circumference} strokeDashoffset={offset} style={{ transition: "stroke-dashoffset 1s ease" }} />
        <text x="100" y="84" textAnchor="middle" fontSize="40" fontWeight="700" fill={color}>{grade}</text>
        <text x="100" y="108" textAnchor="middle" fontSize="13" fill="#475569">{score} / 100 risk</text>
      </svg>
    </div>
  );
}
