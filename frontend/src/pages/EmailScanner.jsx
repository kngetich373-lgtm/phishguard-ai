import { useEffect, useState } from "react";
import { Mail, Loader2, AlertTriangle, Info } from "lucide-react";
import { scanEmail, gmailStatus } from "../api/client";
import { Card, Button, VerdictBadge } from "../components/ui";
import RiskGauge from "../components/RiskGauge";

export default function EmailScanner() {
  const [form, setForm] = useState({ sender: "", subject: "", body: "" });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [gmailConfigured, setGmailConfigured] = useState(false);

  useEffect(() => {
    gmailStatus().then((res) => setGmailConfigured(res.data.configured)).catch(() => {});
  }, []);

  const update = (key) => (e) => setForm({ ...form, [key]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.body.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await scanEmail(form.subject, form.body, form.sender || undefined);
      setResult(res.data);
    } catch {
      setError("Couldn't scan that email. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-8 py-12">
      <div className="flex items-center gap-2.5 mb-1">
        <Mail className="w-6 h-6 text-brand" />
        <h1 className="font-display text-2xl font-semibold">Email Scanner</h1>
      </div>
      <p className="text-ink/50 text-[14px] mb-4">Paste an email's sender, subject, and body to check it for phishing indicators.</p>

      <div className="flex items-start gap-2 bg-brand/[0.05] border border-brand/15 rounded-lg px-4 py-3 mb-6">
        <Info className="w-4 h-4 text-brand mt-0.5 shrink-0" />
        <p className="text-[12.5px] text-ink/60 leading-relaxed">
          {gmailConfigured
            ? "Gmail sync is configured on this deployment — connect your inbox from Settings to auto-scan incoming mail."
            : "Gmail auto-sync isn't configured on this deployment yet (needs Google OAuth credentials in the backend .env). Paste an email below to scan it manually — the same detection engine is used either way."}
        </p>
      </div>

      <Card className="p-6">
        <form onSubmit={handleSubmit} className="space-y-3">
          <input
            value={form.sender} onChange={update("sender")}
            placeholder="Sender address, e.g. security@paypa1.com"
            className="w-full border border-line rounded-md px-3.5 py-2.5 text-[14px] font-mono focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-brand"
          />
          <input
            value={form.subject} onChange={update("subject")}
            placeholder="Subject line"
            className="w-full border border-line rounded-md px-3.5 py-2.5 text-[14px] focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-brand"
          />
          <textarea
            value={form.body} onChange={update("body")}
            rows={7}
            placeholder="Paste the full email body here…"
            className="w-full border border-line rounded-md px-3.5 py-2.5 text-[14px] focus:outline-none focus:ring-2 focus:ring-brand/30 focus:border-brand resize-none"
          />
          <Button type="submit" disabled={loading}>
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Scan email"}
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
              <p className="text-[12.5px] font-semibold text-ink/45 tracking-wide mb-2 mt-4">WHY THIS VERDICT</p>
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
