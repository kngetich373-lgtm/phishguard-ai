import { Link } from "react-router-dom";
import { ShieldCheck, Link2, MessageSquareWarning, Bell, LayoutDashboard, Puzzle, FileBarChart, BookOpen, LifeBuoy, FileText, ArrowRight } from "lucide-react";

const COLUMNS = [
  {
    title: "DETECTION TOOLS",
    items: [
      { icon: Link2, name: "URL Scanner", desc: "Scan suspicious links instantly for threats.", to: "/scan/url" },
      { icon: MessageSquareWarning, name: "SMS Analyzer", desc: "Identify scam messages before you click.", to: "/scan/sms" },
      { icon: Bell, name: "Real-Time Alerts", desc: "Get notified of phishing attempts fast.", to: "/alerts" },
    ],
  },
  {
    title: "FOR BUSINESS",
    items: [
      { icon: LayoutDashboard, name: "Team Dashboard", desc: "Monitor threats across your organization.", to: "/dashboard" },
      { icon: Puzzle, name: "API Access", desc: "Integrate phishing detection into your workflow.", to: "/api-access" },
      { icon: FileBarChart, name: "Reporting Suite", desc: "Generate detailed security reports easily.", to: "/reports" },
    ],
  },
  {
    title: "RESOURCES",
    items: [
      { icon: BookOpen, name: "Knowledge Base", desc: "Learn how to spot phishing and scams.", to: "/scan/email" },
      { icon: FileText, name: "Guides", desc: "Step-by-step help for safer browsing.", to: "/scan/url" },
      { icon: LifeBuoy, name: "Support Center", desc: "Get answers from our friendly team.", to: "/scan/sms" },
    ],
  },
];

export default function Landing() {
  return (
    <div className="max-w-6xl mx-auto px-8 py-14">
      <div className="flex items-center gap-2.5 mb-2">
        <ShieldCheck className="w-8 h-8 text-brand" strokeWidth={2.2} />
        <h1 className="font-display text-2xl font-semibold tracking-tight">PhishGuard AI</h1>
      </div>
      <p className="text-ink/55 text-[15px] mb-12 max-w-xl">
        AI-powered detection for phishing URLs, scam texts, and malicious email — built for individuals and security teams.
      </p>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_1fr_1fr_320px] gap-10">
        {COLUMNS.map((col) => (
          <div key={col.title}>
            <p className="text-[11px] font-semibold tracking-wider text-ink/40 mb-5">{col.title}</p>
            <div className="space-y-6">
              {col.items.map(({ icon: Icon, name, desc, to }) => (
                <Link key={name} to={to} className="flex items-start gap-3 group">
                  <Icon className="w-[18px] h-[18px] mt-0.5 text-ink/70 group-hover:text-brand transition-colors shrink-0" strokeWidth={1.8} />
                  <div>
                    <p className="text-[14px] font-semibold text-ink group-hover:text-brand transition-colors">{name}</p>
                    <p className="text-[13px] text-ink/50 leading-snug mt-0.5">{desc}</p>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        ))}

        <div className="bg-ink text-white rounded-2xl p-7 h-fit relative overflow-hidden scanline">
          <div className="relative">
            <h3 className="font-display text-xl font-semibold leading-snug">
              Stop phishing before it starts
            </h3>
            <p className="text-white/60 text-[13.5px] mt-3 leading-relaxed">
              Protect your business with AI-powered detection and instant alerts.
            </p>
            <Link
              to="/register"
              className="inline-flex items-center gap-1.5 mt-6 text-[13.5px] font-semibold text-white hover:gap-2.5 transition-all"
            >
              Get started <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
