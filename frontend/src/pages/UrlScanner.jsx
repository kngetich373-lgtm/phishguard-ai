import { useState } from "react";
import { Link2, Loader2, AlertTriangle } from "lucide-react";
import { scanUrl } from "../api/client";
import { Card, Button, VerdictBadge } from "../components/ui";
import RiskGauge from "../components/RiskGauge";

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await scanUrl(url.trim());
      setResult(res.data);
    } catch (err) {
      setError("Couldn't scan that URL. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-8 py-12">
      <div className="flex items-center gap-2.5 mb-1">
        <Link2 className="w-6 h-6 text-brand" />
        <h1 className="font-display text-2xl font-semibold">URL Scanner</h1>
      </div>
      <p className="text-ink/50 text-[14px] mb-8">Paste any link to check it for phishing indicators before you click.</p>

      <Card className="p-6">
        <form onSubmit={handleSubmit} className="flex gap-3">
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/reset-password"
            className="flex-1 border border-line rounded-md px-3.5 py-2.5 text-[14px] font-mono focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-brand"
          />
          <Button type="submit" disabled={loading}>
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Scan URL"}
          </Button>
        </form>
      </Card>

      {error && (
        <div className="mt-6 flex items-center gap-2 text-danger text-[13.5px]">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {result && (
        <Card className="mt-6 p-8">
          <div className="flex flex-col md:flex-row gap-8 items-center md:items-start">
            <RiskGauge score={result.risk_score} verdict={result.verdict} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <VerdictBadge verdict={result.verdict} />
              </div>
              <p className="font-mono text-[13px] text-ink/70 break-all mb-4">{result.input_value}</p>
              <p className="text-[12.5px] font-semibold text-ink/45 tracking-wide mb-2">WHY THIS VERDICT</p>
              <ul className="space-y-1.5">
                {result.reasons.map((r, i) => (
                  <li key={i} className="text-[13.5px] text-ink/75 flex gap-2">
                    <span className="text-ink/30">—</span> {r}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
