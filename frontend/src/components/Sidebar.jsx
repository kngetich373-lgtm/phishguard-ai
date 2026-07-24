import { NavLink, useNavigate } from "react-router-dom";
import {
  ShieldCheck, Link2, MessageSquareWarning, Mail, Bell,
  LayoutDashboard, FileBarChart, Users, KeyRound, LogOut,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const NAV = [
  { section: "Detection Tools", items: [
    { to: "/scan/url", label: "URL Scanner", icon: Link2 },
    { to: "/scan/sms", label: "SMS Analyzer", icon: MessageSquareWarning },
    { to: "/scan/email", label: "Email Scanner", icon: Mail },
    { to: "/alerts", label: "Real-Time Alerts", icon: Bell },
  ]},
  { section: "For Business", items: [
    { to: "/dashboard", label: "Team Dashboard", icon: LayoutDashboard },
    { to: "/team", label: "Team", icon: Users },
    { to: "/api-access", label: "API Access", icon: KeyRound },
    { to: "/reports", label: "Reporting Suite", icon: FileBarChart },
  ]},
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <aside className="w-64 shrink-0 h-screen sticky top-0 border-r border-line bg-white flex flex-col">
      <div className="px-6 py-6 flex items-center gap-2 border-b border-line">
        <ShieldCheck className="w-6 h-6 text-brand" strokeWidth={2.2} />
        <span className="font-display font-semibold text-[17px] tracking-tight">PhishGuard AI</span>
      </div>

      <nav className="flex-1 overflow-y-auto px-4 py-5 space-y-7">
        {NAV.map((group) => (
          <div key={group.section}>
            <p className="px-2 mb-2 text-[11px] font-semibold tracking-wider text-ink/40 uppercase">
              {group.section}
            </p>
            <div className="space-y-0.5">
              {group.items.map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 px-2.5 py-2 rounded-md text-[13.5px] font-medium transition-colors ${
                      isActive
                        ? "bg-brand/[0.08] text-brand"
                        : "text-ink/70 hover:bg-ink/[0.04] hover:text-ink"
                    }`
                  }
                >
                  <Icon className="w-[17px] h-[17px]" strokeWidth={2} />
                  {label}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="px-4 py-4 border-t border-line">
        {user ? (
          <div className="flex items-center justify-between px-2">
            <div className="min-w-0">
              <p className="text-[13px] font-medium truncate">{user.full_name || user.email}</p>
              <p className="text-[11.5px] text-ink/45 truncate">{user.email}</p>
            </div>
            <button
              onClick={() => { logout(); navigate("/"); }}
              className="p-1.5 rounded-md text-ink/40 hover:text-danger hover:bg-danger-soft transition-colors"
              title="Log out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <button
            onClick={() => navigate("/login")}
            className="w-full text-[13px] font-medium bg-brand text-white rounded-md py-2 hover:bg-brand-dark transition-colors"
          >
            Log in
          </button>
        )}
      </div>
    </aside>
  );
}
