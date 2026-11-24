export function Card({ children, className = "" }) {
  return (
    <div className={`bg-white border border-line rounded-xl shadow-card ${className}`}>
      {children}
    </div>
  );
}

const VERDICT_MAP = {
  safe: "bg-signal-soft text-signal",
  suspicious: "bg-caution-soft text-caution",
  malicious: "bg-danger-soft text-danger",
  inconclusive: "bg-ink/[0.08] text-ink/70",
};

export function VerdictBadge({ verdict }) {
  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-[11.5px] font-semibold tracking-wide uppercase ${VERDICT_MAP[verdict] || ""}`}>
      {verdict}
    </span>
  );
}

export function Stat({ label, value, accent }) {
  return (
    <Card className="p-5">
      <p className="text-[12px] font-medium text-ink/45 tracking-wide">{label}</p>
      <p className={`mt-1.5 text-3xl font-display font-semibold ${accent || "text-ink"}`}>{value}</p>
    </Card>
  );
}

export function Button({ children, variant = "primary", className = "", ...props }) {
  const base = "inline-flex items-center justify-center gap-2 rounded-md text-[13.5px] font-medium px-4 py-2.5 transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  const variants = {
    primary: "bg-brand text-white hover:bg-brand-dark",
    secondary: "bg-white border border-line text-ink hover:bg-ink/[0.03]",
    ghost: "text-ink/60 hover:text-ink hover:bg-ink/[0.04]",
  };
  return (
    <button className={`${base} ${variants[variant]} ${className}`} {...props}>
      {children}
    </button>
  );
}
