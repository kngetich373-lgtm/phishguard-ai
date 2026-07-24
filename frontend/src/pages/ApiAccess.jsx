import { useEffect, useState } from "react";
import { KeyRound, Plus, Copy, Check } from "lucide-react";
import { fetchApiKeys, createApiKey } from "../api/client";

const SNIPPET = `curl -X POST https://your-domain.com/api/scan/url \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://example.com/reset-password"}'`;

export default function ApiAccess() {
  const [keys, setKeys] = useState([]);
  const [creating, setCreating] = useState(false);
  const [copiedId, setCopiedId] = useState(null);

  const load = () => fetchApiKeys().then((res) => setKeys(res.data)).catch(() => {});

  // BUG FIX: useEffect(load, []) passed `load` itself as the effect fn.
  // `load` returns a Promise (from .then().catch()) - React expects an
  // effect to return either undefined or a cleanup function, and later
  // tried calling that Promise as a cleanup function on unmount, which
  // threw "destroy is not a function" and crashed the whole tree (no
  // error boundary above it to contain the damage). Wrapping it means
  // the effect itself returns undefined, as it should.
  useEffect(() => {
    load();
  }, []);

  const handleCreate = async () => {
    setCreating(true);
    try {
      await createApiKey("Default key");
      load();
    } finally {
      setCreating(false);
    }
  };

  const handleCopy = (k) => {
    navigator.clipboard.writeText(k.key);
    setCopiedId(k.id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  return (
    <div className="min-h-full bg-black relative">
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-96"
        style={{
          background: "radial-gradient(ellipse 50% 100% at 50% 0%, rgba(16,185,129,0.08), transparent 70%)",
        }}
      />

      <div className="relative max-w-3xl mx-auto px-8 py-12">
        <div className="flex items-center gap-2.5 mb-1">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 ring-1 ring-emerald-500/30 flex items-center justify-center">
            <KeyRound className="w-4.5 h-4.5 text-emerald-400" />
          </div>
          <h1 className="font-display text-2xl font-semibold text-white">API Access</h1>
        </div>
        <p className="text-white/40 text-[14px] mb-8 ml-[42px]">
          Integrate URL, SMS, and email phishing detection directly into your product.
        </p>

        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <p className="text-[13px] font-semibold text-white/60">Your API keys</p>
            <button
              onClick={handleCreate}
              disabled={creating}
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 text-black text-[13px] font-semibold px-3.5 py-2
                         hover:bg-emerald-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Plus className="w-4 h-4" /> {creating ? "Creating…" : "New key"}
            </button>
          </div>

          {keys.length === 0 ? (
            <p className="text-[13.5px] text-white/30">No API keys yet. Create one to start integrating.</p>
          ) : (
            <div className="space-y-2">
              {keys.map((k) => (
                <div
                  key={k.id}
                  className="flex items-center justify-between border border-white/10 bg-white/[0.02] rounded-lg px-3.5 py-2.5"
                >
                  <div className="min-w-0">
                    <p className="text-[13px] font-medium text-white/80">{k.label}</p>
                    <p className="text-[12.5px] font-mono text-white/40 truncate">{k.key}</p>
                  </div>
                  <button
                    onClick={() => handleCopy(k)}
                    className="p-1.5 text-white/30 hover:text-emerald-400 transition-colors shrink-0 ml-2"
                  >
                    {copiedId === k.id ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-6">
          <p className="text-[13px] font-semibold text-white/60 mb-3">Quick start</p>
          <pre className="bg-black border border-white/10 text-emerald-300/90 rounded-lg p-4 text-[12.5px] font-mono overflow-x-auto leading-relaxed">
{SNIPPET}
          </pre>
          <p className="text-[12.5px] text-white/35 mt-3">
            Endpoints:{" "}
            <code className="font-mono text-white/60 bg-white/5 px-1.5 py-0.5 rounded">POST /api/scan/url</code>,{" "}
            <code className="font-mono text-white/60 bg-white/5 px-1.5 py-0.5 rounded">POST /api/scan/sms</code>,{" "}
            <code className="font-mono text-white/60 bg-white/5 px-1.5 py-0.5 rounded">POST /api/scan/email</code>.
            Full interactive docs are available at{" "}
            <code className="font-mono text-white/60 bg-white/5 px-1.5 py-0.5 rounded">/docs</code> on your backend deployment.
          </p>
        </div>
      </div>
    </div>
  );
}
