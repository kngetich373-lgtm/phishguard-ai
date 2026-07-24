import { useEffect, useRef, useState } from "react";
import { LayoutDashboard, ShieldCheck, ShieldAlert, ShieldX, Activity } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";
import { fetchSummary } from "../api/client";

/* ---------------------------------------------------------------
   Palette (drop into tailwind config if you want named tokens):
   bg        #05080A   -- near-black, faint green cast
   surface   #0D1512   -- card base
   surface-2 #121D18   -- card hover / elevated
   line      #1E2B25   -- hairline borders
   emerald   #10B981   -- primary accent
   emerald-2 #34D399   -- bright accent / glow
   amber     #D9A441   -- suspicious
   red       #E5484D   -- malicious
   ink       #E8F2EC   -- primary text
   ink/60    #8FA39A   -- secondary text
------------------------------------------------------------------ */

const COLORS = { safe: "#10B981", suspicious: "#D9A441", malicious: "#E5484D" };

function useCountUp(target, duration = 900) {
  const [value, setValue] = useState(0);
  const raf = useRef(null);
  useEffect(() => {
    if (typeof target !== "number") return;
    const start = performance.now();
    const from = 0;
    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(Math.round(from + (target - from) * eased));
      if (t < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [target, duration]);
  return value;
}

function Card({ children, className = "", delay = 0 }) {
  return (
    <div
      className={`rounded-2xl border border-[#1E2B25] bg-[#0D1512]/80 backdrop-blur-sm
                  shadow-[0_1px_0_rgba(255,255,255,0.02)_inset]
                  animate-[fadeInUp_.6s_ease_both] ${className}`}
      style={{ animationDelay: `${delay}ms` }}
    >
      {children}
    </div>
  );
}

function Stat({ label, value, accent, icon: Icon, delay }) {
  const n = useCountUp(typeof value === "number" ? value : 0);
  return (
    <Card delay={delay} className="p-5 relative overflow-hidden group hover:border-[#2C3F35] transition-colors duration-300">
      <div className="absolute -right-4 -top-4 w-20 h-20 rounded-full bg-emerald-500/5 blur-2xl group-hover:bg-emerald-500/10 transition-all duration-500" />
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11.5px] font-medium tracking-wide uppercase text-[#8FA39A]">{label}</p>
        {Icon && <Icon className={`w-4 h-4 ${accent || "text-[#10B981]"}`} strokeWidth={2} />}
      </div>
      <p className={`font-mono text-[28px] font-semibold tabular-nums ${accent || "text-[#E8F2EC]"}`}>
        {n.toLocaleString()}
      </p>
    </Card>
  );
}

function VerdictBadge({ verdict }) {
  const map = {
    safe: { label: "Safe", cls: "text-[#10B981] bg-[#10B981]/10 border-[#10B981]/25" },
    suspicious: { label: "Suspicious", cls: "text-[#D9A441] bg-[#D9A441]/10 border-[#D9A441]/25" },
    malicious: { label: "Malicious", cls: "text-[#E5484D] bg-[#E5484D]/10 border-[#E5484D]/25" },
  };
  const v = map[verdict] || map.safe;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border ${v.cls}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {v.label}
    </span>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-[#1E2B25] bg-[#0A100D] px-3 py-2 text-[12px] shadow-lg">
      {label && <p className="text-[#8FA39A] mb-1">{label}</p>}
      {payload.map((p, i) => (
        <p key={i} className="text-[#E8F2EC] font-mono">
          {p.name}: <span className="font-semibold">{p.value}</span>
        </p>
      ))}
    </div>
  );
};

export default function Dashboard() {
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    fetchSummary().then((res) => setSummary(res.data)).catch(() => {});
  }, []);

  if (!summary) {
    return (
      <div className="min-h-screen bg-[#05080A] flex items-center justify-center">
        <div className="flex items-center gap-3 text-[#8FA39A] text-[14px]">
          <Activity className="w-4 h-4 animate-pulse text-[#10B981]" />
          Loading dashboard…
        </div>
      </div>
    );
  }

  const pieData = [
    { name: "Safe", value: summary.safe_count, key: "safe" },
    { name: "Suspicious", value: summary.suspicious_count, key: "suspicious" },
    { name: "Malicious", value: summary.malicious_count, key: "malicious" },
  ];

  const typeData = Object.entries(summary.scans_by_type).map(([type, count]) => ({ type, count }));

  return (
    <div className="min-h-screen bg-[#05080A] relative">
      {/* ambient grid texture */}
      <div
        className="pointer-events-none fixed inset-0 opacity-[0.05]"
        style={{
          backgroundImage:
            "linear-gradient(#10B981 1px, transparent 1px), linear-gradient(90deg, #10B981 1px, transparent 1px)",
          backgroundSize: "44px 44px",
        }}
      />
      <div className="pointer-events-none fixed -top-40 left-1/2 -translate-x-1/2 w-[900px] h-[500px] bg-emerald-500/[0.07] blur-[120px] rounded-full" />

      <div className="max-w-6xl mx-auto px-8 py-12 relative">
        {/* Header with signature radar-sweep mark */}
        <div className="flex items-center gap-3 mb-1">
          <div className="relative w-9 h-9 flex items-center justify-center">
            <span
              className="absolute inset-0 rounded-full border border-[#10B981]/30"
              style={{ animation: "radarPulse 2.4s ease-out infinite" }}
            />
            <span
              className="absolute inset-0 rounded-full"
              style={{
                background: "conic-gradient(from 0deg, #10B98155, transparent 70%)",
                animation: "spin 3s linear infinite",
              }}
            />
            <div className="relative w-8 h-8 rounded-full bg-[#0D1512] border border-[#1E2B25] flex items-center justify-center">
              <LayoutDashboard className="w-4 h-4 text-[#10B981]" />
            </div>
          </div>
          <h1 className="font-semibold text-2xl text-[#E8F2EC] tracking-tight">Team Dashboard</h1>
        </div>
        <p className="text-[#8FA39A] text-[14px] mb-8 ml-12">
          Monitor phishing threats detected across your organization.
        </p>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <Stat label="Total scans" value={summary.total_scans} icon={Activity} delay={0} />
          <Stat label="Safe" value={summary.safe_count} accent="text-[#10B981]" icon={ShieldCheck} delay={80} />
          <Stat label="Suspicious" value={summary.suspicious_count} accent="text-[#D9A441]" icon={ShieldAlert} delay={160} />
          <Stat label="Malicious" value={summary.malicious_count} accent="text-[#E5484D]" icon={ShieldX} delay={240} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <Card className="p-6" delay={320}>
            <p className="text-[13px] font-semibold text-[#8FA39A] mb-4 tracking-wide uppercase">Verdict breakdown</p>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={3} stroke="none">
                  {pieData.map((entry) => (
                    <Cell key={entry.key} fill={COLORS[entry.key]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </Card>

          <Card className="p-6" delay={400}>
            <p className="text-[13px] font-semibold text-[#8FA39A] mb-4 tracking-wide uppercase">Scans by channel</p>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={typeData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E2B25" vertical={false} />
                <XAxis dataKey="type" tick={{ fontSize: 12, fill: "#8FA39A" }} axisLine={{ stroke: "#1E2B25" }} tickLine={false} />
                <YAxis tick={{ fontSize: 12, fill: "#8FA39A" }} allowDecimals={false} axisLine={{ stroke: "#1E2B25" }} tickLine={false} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: "#10B98110" }} />
                <Bar dataKey="count" fill="#10B981" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </div>

        <Card className="p-6" delay={480}>
          <p className="text-[13px] font-semibold text-[#8FA39A] mb-4 tracking-wide uppercase">Recent scans</p>
          <div>
            {summary.recent_scans.length === 0 && (
              <p className="text-[13.5px] text-[#8FA39A]">No scans yet.</p>
            )}
            {summary.recent_scans.map((s, i) => (
              <div
                key={s.id}
                className="flex items-center justify-between py-2.5 border-b border-[#1E2B25] last:border-0
                           hover:bg-[#10B981]/[0.03] transition-colors duration-200 rounded-lg px-2 -mx-2
                           animate-[fadeInUp_.5s_ease_both]"
                style={{ animationDelay: `${560 + i * 40}ms` }}
              >
                <div className="min-w-0 flex-1">
                  <p className="text-[13.5px] font-mono text-[#E8F2EC]/90 truncate">{s.input_value}</p>
                  <p className="text-[11.5px] text-[#8FA39A]">
                    {s.scan_type.toUpperCase()} · {new Date(s.created_at).toLocaleString()}
                  </p>
                </div>
                <VerdictBadge verdict={s.verdict} />
              </div>
            ))}
          </div>
        </Card>
      </div>

      <style>{`
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes radarPulse {
          0% { transform: scale(0.9); opacity: 0.8; }
          100% { transform: scale(2.2); opacity: 0; }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @media (prefers-reduced-motion: reduce) {
          * { animation: none !important; transition: none !important; }
        }
      `}</style>
    </div>
  );
}
