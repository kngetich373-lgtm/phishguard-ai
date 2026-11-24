import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import ProtectedRoute from "./components/ProtectedRoute";

import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";
import UrlScanner from "./pages/UrlScanner";
import SmsAnalyzer from "./pages/SmsAnalyzer";
import EmailScanner from "./pages/EmailScanner";
import Alerts from "./pages/Alerts";
import Dashboard from "./pages/Dashboard";
import Reports from "./pages/Reports";
import Team from "./pages/Team";
import ApiAccess from "./pages/ApiAccess";

function AppShell({ children }) {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 min-w-0">{children}</main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      <Route path="/" element={<AppShell><Landing /></AppShell>} />
      <Route path="/scan/url" element={<AppShell><UrlScanner /></AppShell>} />
      <Route path="/scan/sms" element={<AppShell><SmsAnalyzer /></AppShell>} />
      <Route path="/scan/email" element={<AppShell><EmailScanner /></AppShell>} />
      <Route path="/alerts" element={<AppShell><Alerts /></AppShell>} />

      <Route path="/dashboard" element={<AppShell><ProtectedRoute><Dashboard /></ProtectedRoute></AppShell>} />
      <Route path="/reports" element={<AppShell><ProtectedRoute><Reports /></ProtectedRoute></AppShell>} />
      <Route path="/team" element={<AppShell><ProtectedRoute><Team /></ProtectedRoute></AppShell>} />
      <Route path="/api-access" element={<AppShell><ProtectedRoute><ApiAccess /></ProtectedRoute></AppShell>} />
    </Routes>
  );
}
