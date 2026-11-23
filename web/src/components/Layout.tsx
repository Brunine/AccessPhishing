import { useState, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useSession } from "../auth";
import { ErrorBanner } from "./ui";

const NAV = [
  { to: "/overview", label: "Overview" },
  { to: "/campaigns", label: "Campaigns" },
  { to: "/contacts", label: "Contacts" },
  { to: "/templates", label: "Templates" },
  { to: "/sending-profiles", label: "Sending Profiles" },
  { to: "/approvals", label: "Approvals" },
  { to: "/recon", label: "Recon" },
  { to: "/activity", label: "Activity" },
  { to: "/settings", label: "Settings" },
];

export function KeyGate() {
  const { signIn } = useSession();
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await signIn(value.trim());
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="card w-full max-w-md">
        <h1 className="text-lg font-semibold text-slate-100">
          PhishForge Console
        </h1>
        <p className="mt-1 mb-4 text-sm text-slate-400">
          Enter your operator API key. It is stored only in this browser
          (localStorage) and sent as the <code>X-API-Key</code> header.
        </p>
        <ErrorBanner error={err} />
        <input
          className="input font-mono"
          placeholder="pf_<keyID>.<secret>"
          value={value}
          autoFocus
          onChange={(e) => setValue(e.target.value)}
        />
        <button
          className="btn-primary mt-4 w-full"
          disabled={busy || value.trim() === ""}
        >
          {busy ? "Verifying…" : "Continue"}
        </button>
      </form>
    </div>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const { role, isAdmin, signOut } = useSession();
  const nav = isAdmin
    ? [{ to: "/platform", label: "Platform" }, { to: "/tenants", label: "Tenants" }, ...NAV]
    : NAV;

  return (
    <div className="min-h-screen">
      <header className="border-b border-ink-700 bg-ink-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center gap-4 px-4 py-3">
          <span className="font-semibold text-indigo-300">PhishForge</span>
          <nav className="flex flex-wrap gap-1 text-sm">
            {nav.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                className={({ isActive }) =>
                  `rounded px-2.5 py-1 ${
                    isActive
                      ? "bg-ink-700 text-slate-100"
                      : "text-slate-400 hover:text-slate-200"
                  }`
                }
              >
                {n.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-xs text-slate-400">
            <span className="rounded bg-ink-700 px-2 py-0.5 uppercase tracking-wide">
              {role ?? "—"}
            </span>
            <button
              onClick={signOut}
              className="text-slate-400 hover:text-rose-300"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
    </div>
  );
}
