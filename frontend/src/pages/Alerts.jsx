import { useEffect, useRef, useState } from "react";
import { Bell, Radio } from "lucide-react";
import { fetchAlerts } from "../api/client";
import { Card, VerdictBadge } from "../components/ui";

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    fetchAlerts().then((res) => setAlerts(res.data)).catch(() => {});

    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    // In dev, Vite proxies /api but not raw ws upgrades on a different path reliably,
    // so we connect straight to the backend port for the socket.
    const wsUrl = `${protocol}://${window.location.hostname}:8000/api/alerts/ws`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => setConnected(false);
      ws.onerror = () => setConnected(false);
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "alert") {
          setAlerts((prev) => [
            { id: crypto.randomUUID(), title: data.title, message: data.message, severity: data.severity, created_at: data.created_at, read: false },
            ...prev,
          ]);
        }
      };
      return () => ws.close();
    } catch {
      setConnected(false);
    }
  }, []);

  return (
    <div className="max-w-3xl mx-auto px-8 py-12">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2.5">
          <Bell className="w-6 h-6 text-brand" />
          <h1 className="font-display text-2xl font-semibold">Real-Time Alerts</h1>
        </div>
        <div className={`flex items-center gap-1.5 text-[12px] font-medium ${connected ? "text-signal" : "text-ink/35"}`}>
          <Radio className="w-3.5 h-3.5" />
          {connected ? "Live" : "Connecting…"}
        </div>
      </div>
      <p className="text-ink/50 text-[14px] mb-8">Suspicious and malicious scans across your account appear here instantly.</p>

      {alerts.length === 0 ? (
        <Card className="p-10 text-center">
          <p className="text-ink/50 text-[14px]">No alerts yet. Run a scan from URL Scanner, SMS Analyzer, or Email Scanner to see it here.</p>
        </Card>
      ) : (
        <div className="space-y-3">
          {alerts.map((alert) => (
            <Card key={alert.id} className="p-4 flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <VerdictBadge verdict={alert.severity} />
                  <span className="text-[11.5px] text-ink/40">
                    {new Date(alert.created_at).toLocaleString()}
                  </span>
                </div>
                <p className="text-[13.5px] font-medium text-ink truncate">{alert.title}</p>
                <p className="text-[13px] text-ink/55 truncate mt-0.5">{alert.message}</p>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
