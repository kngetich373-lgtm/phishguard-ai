import { useState } from "react";
import { MessageSquareWarning, Loader2, AlertTriangle } from "lucide-react";
import { scanSms } from "../api/client";
import { Card, Button, VerdictBadge } from "../components/ui";
import RiskGauge from "../components/RiskGauge";

export default function SmsAnalyzer() {
  const [message, setMessage] = useState("");
  const [sender, setSender] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!message.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await scanSms(message.trim(), sender.trim() || undefined);
      setResult(res.data);
    } catch {
      setError("Couldn't analyze that message. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-8 py-12">
      <div className="flex items-center gap-2.5 mb-1">
        <MessageSquareWarning className="w-6 h-6 text-brand" />
        <h1 className="font-display text-2xl font-semibold">SMS Analyzer</h1>
      </div>
      <p className="text-ink/50 text-[14px] mb-8">Paste a text message to check it for smishing (SMS phishing) indicators.</p>

      <Card className="p-6">
        <form onSubmit={handleSubmit} className="space-y-3">
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            rows={4}
            placeholder="Your account has been suspended. Verify now at bit.ly/..."
            className="w-full border border-line rounded-md px-3.5 py-2.5 text-[14px] focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-brand resize-none"
          />
          <div className="flex gap-3">
            <input
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              placeholder="Sender number (optional)"
              className="flex-1 border border-line rounded-md px-3.5 py-2.5 text-[14px] font-mono focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-brand"
            />
            <Button type="submit" disabled={loading}>
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Analyze message"}
            </Button>
          </div>
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
              <p className="text-[13.5px] text-ink/70 mb-4 italic">"{result.input_value}"</p>
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
