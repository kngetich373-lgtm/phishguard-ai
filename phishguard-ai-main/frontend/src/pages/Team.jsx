import { useEffect, useState } from "react";
import { Users, UserPlus } from "lucide-react";
import { fetchMyTeam, inviteMember } from "../api/client";
import { Card, Button } from "../components/ui";
import { useAuth } from "../context/AuthContext";

export default function Team() {
  const { user } = useAuth();
  const [team, setTeam] = useState(null);
  const [error, setError] = useState("");
  const [inviteForm, setInviteForm] = useState({ email: "", password: "", full_name: "" });
  const [inviting, setInviting] = useState(false);

  const load = () => {
    fetchMyTeam()
      .then((res) => setTeam(res.data))
      .catch((err) => setError(err.response?.data?.detail || "No team found."));
  };

  useEffect(load, []);

  const handleInvite = async (e) => {
    e.preventDefault();
    setInviting(true);
    try {
      await inviteMember(inviteForm);
      setInviteForm({ email: "", password: "", full_name: "" });
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Couldn't invite that member.");
    } finally {
      setInviting(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-8 py-12">
      <div className="flex items-center gap-2.5 mb-1">
        <Users className="w-6 h-6 text-brand" />
        <h1 className="font-display text-2xl font-semibold">Team</h1>
      </div>
      <p className="text-ink/50 text-[14px] mb-8">Manage who has access to your organization's PhishGuard workspace.</p>

      {!team ? (
        <Card className="p-8 text-center">
          <p className="text-ink/55 text-[14px]">{error || "Loading…"}</p>
          {error && <p className="text-ink/40 text-[13px] mt-2">Create a team name during sign-up to unlock team features.</p>}
        </Card>
      ) : (
        <>
          <Card className="p-6 mb-6">
            <p className="text-[13px] font-semibold text-ink/60 mb-4">{team.name} · {team.members.length} member{team.members.length !== 1 ? "s" : ""}</p>
            <div className="space-y-2">
              {team.members.map((m) => (
                <div key={m.id} className="flex items-center justify-between py-2 border-b border-line last:border-0">
                  <div>
                    <p className="text-[13.5px] font-medium">{m.full_name || m.email}</p>
                    <p className="text-[12px] text-ink/45">{m.email}</p>
                  </div>
                  {m.is_admin && <span className="text-[11px] font-semibold text-brand bg-brand/[0.08] px-2 py-0.5 rounded-full">ADMIN</span>}
                </div>
              ))}
            </div>
          </Card>

          {user?.is_admin && (
            <Card className="p-6">
              <p className="text-[13px] font-semibold text-ink/60 mb-4 flex items-center gap-1.5"><UserPlus className="w-4 h-4" /> Invite a member</p>
              <form onSubmit={handleInvite} className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <input required placeholder="Full name" value={inviteForm.full_name}
                  onChange={(e) => setInviteForm({ ...inviteForm, full_name: e.target.value })}
                  className="border border-line rounded-md px-3 py-2 text-[13.5px] focus:outline-none focus:ring-2 focus:ring-brand/30" />
                <input required type="email" placeholder="Email" value={inviteForm.email}
                  onChange={(e) => setInviteForm({ ...inviteForm, email: e.target.value })}
                  className="border border-line rounded-md px-3 py-2 text-[13.5px] focus:outline-none focus:ring-2 focus:ring-brand/30" />
                <input required type="password" minLength={8} placeholder="Temp password" value={inviteForm.password}
                  onChange={(e) => setInviteForm({ ...inviteForm, password: e.target.value })}
                  className="border border-line rounded-md px-3 py-2 text-[13.5px] focus:outline-none focus:ring-2 focus:ring-brand/30" />
                <Button type="submit" disabled={inviting} className="md:col-span-3 w-fit">
                  {inviting ? "Sending…" : "Send invite"}
                </Button>
              </form>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
