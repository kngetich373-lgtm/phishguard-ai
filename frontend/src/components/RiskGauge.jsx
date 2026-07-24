const VERDICT_STYLES = {
  safe: { color: "#1E6F5C", label: "Safe" },
  suspicious: { color: "#B7791F", label: "Suspicious" },
  malicious: { color: "#B42318", label: "Malicious" },
};

export default function RiskGauge({ score, verdict }) {
  const style = VERDICT_STYLES[verdict] || VERDICT_STYLES.safe;
  const radius = 70;
  const circumference = Math.PI * radius; // half circle
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference - (clamped / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <svg width="180" height="104" viewBox="0 0 180 104">
        <path
          d="M 20 94 A 70 70 0 0 1 160 94"
          fill="none"
          stroke="#E6E8EC"
          strokeWidth="14"
          strokeLinecap="round"
        />
        <path
          d="M 20 94 A 70 70 0 0 1 160 94"
          fill="none"
          stroke={style.color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.8s ease, stroke 0.3s ease" }}
        />
        <text x="90" y="80" textAnchor="middle" className="font-display" fontSize="30" fontWeight="700" fill="#0B1220">
          {Math.round(clamped)}
        </text>
        <text x="90" y="96" textAnchor="middle" fontSize="10" fill="#0B1220" fillOpacity="0.4" letterSpacing="0.5">
          RISK SCORE
        </text>
      </svg>
      <span
        className="mt-1 px-3 py-1 rounded-full text-[12px] font-semibold tracking-wide"
        style={{ color: style.color, backgroundColor: `${style.color}1A` }}
      >
        {style.label.toUpperCase()}
      </span>
    </div>
  );
}
