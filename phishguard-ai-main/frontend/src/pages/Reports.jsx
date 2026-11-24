import { useEffect, useState } from "react";
import { FileBarChart, Download } from "lucide-react";
import { fetchHistory } from "../api/client";
import { Card, Button, VerdictBadge } from "../components/ui";

export default function Reports() {
  const [history, setHistory] = useState([]);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    fetchHistory().then((res) => setHistory(res.data)).catch(() => {});
  }, []);

  const filtered = filter === "all" ? history : history.filter((h) => h.verdict === filter);

  const exportCsv = () => {
    const rows = [["Type", "Input", "Verdict", "Risk score", "Timestamp"]];
    filtered.forEach((s) => rows.push([s.scan_type, s.input_value.replace(/\n/g, " "), s.verdict, s.risk_score, s.created_at]));
    const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "phishguard-report.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-5xl mx-auto px-8 py-12">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2.5">
          <FileBarChart className="w-6 h-6 text-brand" />
          <h1 className="font-display text-2xl font-semibold">Reporting Suite</h1>
        </div>
        <Button variant="secondary" onClick={exportCsv}>
          <Download className="w-4 h-4" /> Export CSV
        </Button>
      </div>
      <p className="text-ink/50 text-[14px] mb-6">Full history of every URL, SMS, and email scan on your account.</p>

      <div className="flex gap-2 mb-4">
        {["all", "safe", "suspicious", "malicious"].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded-full text-[12.5px] font-medium capitalize border transition-colors ${
              filter === f ? "bg-ink text-white border-ink" : "border-line text-ink/60 hover:bg-ink/[0.04]"
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      <Card className="overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-line bg-ink/[0.015]">
              <th className="px-4 py-3 text-[11.5px] font-semibold text-ink/45 tracking-wide">TYPE</th>
              <th className="px-4 py-3 text-[11.5px] font-semibold text-ink/45 tracking-wide">INPUT</th>
              <th className="px-4 py-3 text-[11.5px] font-semibold text-ink/45 tracking-wide">VERDICT</th>
              <th className="px-4 py-3 text-[11.5px] font-semibold text-ink/45 tracking-wide">SCORE</th>
              <th className="px-4 py-3 text-[11.5px] font-semibold text-ink/45 tracking-wide">WHEN</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => (
              <tr key={s.id} className="border-b border-line last:border-0">
                <td className="px-4 py-3 text-[12.5px] uppercase text-ink/50">{s.scan_type}</td>
                <td className="px-4 py-3 text-[13px] font-mono text-ink/80 max-w-xs truncate">{s.input_value}</td>
                <td className="px-4 py-3"><VerdictBadge verdict={s.verdict} /></td>
                <td className="px-4 py-3 text-[13px] text-ink/70">{Math.round(s.risk_score)}</td>
                <td className="px-4 py-3 text-[12.5px] text-ink/45">{new Date(s.created_at).toLocaleString()}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-10 text-center text-ink/40 text-[13.5px]">No scans match this filter.</td></tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
