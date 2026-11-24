import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ShieldCheck, Mail, Lock, Eye, EyeOff, Loader2, AlertCircle } from "lucide-react";
import { loginUser } from "../api/client";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await loginUser(email, password);
      login(res.data.access_token, res.data.user, res.data.refresh_token);
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed. Check your credentials.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen relative flex items-center justify-center bg-black px-4 overflow-hidden">
      {/* ambient glow */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 60% 50% at 50% 0%, rgba(16,185,129,0.16), transparent 60%)",
        }}
      />
      {/* faint dot grid */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.15]"
        style={{
          backgroundImage:
            "radial-gradient(rgba(16,185,129,0.5) 1px, transparent 1px)",
          backgroundSize: "28px 28px",
        }}
      />

      <div className="relative w-full max-w-sm">
        {/* status line */}
        <div className="flex items-center justify-center gap-2 mb-6 font-mono text-[11px] tracking-widest text-emerald-400/80 uppercase">
          <span className="relative flex h-1.5 w-1.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
          </span>
          Secure connection established
        </div>

        <div className="relative rounded-2xl border border-emerald-500/20 bg-white/[0.02] backdrop-blur-xl shadow-[0_0_60px_-15px_rgba(16,185,129,0.35)] p-8 sm:p-10">
          {/* corner brackets */}
          <span className="absolute -top-px -left-px w-5 h-5 border-t-2 border-l-2 border-emerald-400/60 rounded-tl-xl" />
          <span className="absolute -top-px -right-px w-5 h-5 border-t-2 border-r-2 border-emerald-400/60 rounded-tr-xl" />
          <span className="absolute -bottom-px -left-px w-5 h-5 border-b-2 border-l-2 border-emerald-400/60 rounded-bl-xl" />
          <span className="absolute -bottom-px -right-px w-5 h-5 border-b-2 border-r-2 border-emerald-400/60 rounded-br-xl" />

          <div className="flex flex-col items-center text-center mb-8">
            <div className="w-12 h-12 rounded-xl bg-emerald-500/10 ring-1 ring-emerald-500/30 flex items-center justify-center mb-4">
              <ShieldCheck className="w-6 h-6 text-emerald-400" strokeWidth={2} />
            </div>
            <h1 className="font-display text-2xl font-semibold text-white">Welcome back</h1>
            <p className="text-white/40 text-[13.5px] mt-1.5">
              Sign in to your threat dashboard.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* email */}
            <div className="group relative">
              <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 group-focus-within:text-emerald-400 transition-colors" />
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder=" "
                className="peer w-full bg-white/[0.04] border border-white/10 rounded-xl pl-10 pr-3 pt-5 pb-2 text-[14px] text-white placeholder-transparent
                           focus:outline-none focus:border-emerald-400/60 focus:ring-2 focus:ring-emerald-400/10 transition-colors"
              />
              <label
                htmlFor="email"
                className="absolute left-10 top-4 text-white/40 text-[14px] transition-all pointer-events-none
                           peer-placeholder-shown:top-4 peer-placeholder-shown:text-[14px]
                           peer-focus:top-2 peer-focus:text-[11px] peer-focus:text-emerald-400
                           peer-[:not(:placeholder-shown)]:top-2 peer-[:not(:placeholder-shown)]:text-[11px]"
              >
                Email address
              </label>
            </div>

            {/* password */}
            <div className="group relative">
              <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 group-focus-within:text-emerald-400 transition-colors" />
              <input
                id="password"
                type={showPassword ? "text" : "password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder=" "
                className="peer w-full bg-white/[0.04] border border-white/10 rounded-xl pl-10 pr-10 pt-5 pb-2 text-[14px] text-white placeholder-transparent
                           focus:outline-none focus:border-emerald-400/60 focus:ring-2 focus:ring-emerald-400/10 transition-colors"
              />
              <label
                htmlFor="password"
                className="absolute left-10 top-4 text-white/40 text-[14px] transition-all pointer-events-none
                           peer-placeholder-shown:top-4 peer-placeholder-shown:text-[14px]
                           peer-focus:top-2 peer-focus:text-[11px] peer-focus:text-emerald-400
                           peer-[:not(:placeholder-shown)]:top-2 peer-[:not(:placeholder-shown)]:text-[11px]"
              >
                Password
              </label>
              <button
                type="button"
                onClick={() => setShowPassword((s) => !s)}
                tabIndex={-1}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/70 transition-colors"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <p className="text-red-400 text-[13px] leading-snug">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 rounded-xl bg-emerald-500 text-black font-semibold text-[14px] py-3
                         shadow-[0_0_30px_-8px_rgba(16,185,129,0.6)] transition-all
                         hover:bg-emerald-400 hover:shadow-[0_0_36px_-6px_rgba(16,185,129,0.75)]
                         disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-emerald-500"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Verifying credentials…
                </>
              ) : (
                "Sign in"
              )}
            </button>
          </form>

          <p className="text-[13px] text-white/40 mt-7 text-center">
            New to PhishGuard?{" "}
            <Link to="/register" className="text-emerald-400 hover:text-emerald-300 font-medium transition-colors">
              Create an account
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
