import { useState } from "react";
import { api } from "../api/client";
import type { CreatedAPIKey } from "../api/types";
import { useSession } from "../auth";
import { useAsync } from "../hooks";
import {
  Badge,
  Empty,
  ErrorBanner,
  Field,
  PageHeader,
  Spinner,
  Table,
  timeago,
} from "../components/ui";

export default function Settings() {
  return (
    <div className="space-y-8">
      <PageHeader
        title="Settings"
        subtitle="Operator users and API keys for this tenant."
      />
      <UsersSection />
      <APIKeysSection />
    </div>
  );
}

function UsersSection() {
  const { isAdmin } = useSession();
  const users = useAsync(() => api.users.list());
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("operator");
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<unknown>(null);
  const [actionErr, setActionErr] = useState<unknown>(null);
  const [acting, setActing] = useState<string | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null);
    setBusy(true);
    try {
      await api.users.create({ email: email.trim(), role });
      setEmail("");
      users.reload();
    } catch (e) {
      setFormErr(e);
    } finally {
      setBusy(false);
    }
  }

  async function deactivate(id: string, uemail: string) {
    if (!window.confirm(`Deactivate ${uemail}? Their API keys will stop working immediately.`)) {
      return;
    }
    setActionErr(null);
    setActing(id);
    try {
      await api.users.deactivate(id);
      users.reload();
    } catch (e) {
      setActionErr(e);
    } finally {
      setActing(null);
    }
  }

  return (
    <section>
      <h2 className="mb-3 text-base font-semibold text-slate-100">Users</h2>

      {isAdmin && (
        <form onSubmit={create} className="card mb-4 flex flex-wrap items-end gap-3">
          <div className="min-w-[14rem] flex-1">
            <Field label="Email">
              <input
                className="input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@team.test"
              />
            </Field>
          </div>
          <Field label="Role">
            <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="admin">admin</option>
              <option value="operator">operator</option>
              <option value="viewer">viewer</option>
            </select>
          </Field>
          <button className="btn-primary h-[34px]" disabled={busy || email.trim() === ""}>
            {busy ? "Creating…" : "Add user"}
          </button>
        </form>
      )}
      <ErrorBanner error={formErr} />
      <ErrorBanner error={actionErr} />

      {users.loading ? (
        <Spinner />
      ) : !users.data || users.data.length === 0 ? (
        <Empty>No users.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Email</th>
              <th className="th">Role</th>
              <th className="th">Status</th>
              <th className="th">Created</th>
              {isAdmin && <th className="th"></th>}
            </tr>
          }
        >
          {users.data.map((u) => (
            <tr key={u.id}>
              <td className="td">{u.email}</td>
              <td className="td text-slate-400">{u.role}</td>
              <td className="td">
                <Badge value={u.active ? "active" : "inactive"} />
              </td>
              <td className="td text-slate-400">{timeago(u.created_at)}</td>
              {isAdmin && (
                <td className="td text-right">
                  {u.active ? (
                    <button
                      className="text-slate-500 hover:text-rose-300"
                      disabled={acting === u.id}
                      onClick={() => deactivate(u.id, u.email)}
                    >
                      {acting === u.id ? "…" : "Deactivate"}
                    </button>
                  ) : (
                    <span className="text-xs text-slate-600">—</span>
                  )}
                </td>
              )}
            </tr>
          ))}
        </Table>
      )}
      {!isAdmin && (
        <p className="mt-2 text-xs text-slate-500">Creating and deactivating users requires admin.</p>
      )}
    </section>
  );
}

function APIKeysSection() {
  const keys = useAsync(() => api.apiKeys.list());
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<unknown>(null);
  const [actionErr, setActionErr] = useState<unknown>(null);
  const [created, setCreated] = useState<CreatedAPIKey | null>(null);
  const [copied, setCopied] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null);
    setBusy(true);
    try {
      const k = await api.apiKeys.create(name.trim());
      setCreated(k);
      setCopied(false);
      setName("");
      keys.reload();
    } catch (e) {
      setFormErr(e);
    } finally {
      setBusy(false);
    }
  }

  async function copyToken() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  async function revoke(id: string) {
    if (!window.confirm("Revoke this API key? Any client using it will stop working immediately.")) {
      return;
    }
    setActionErr(null);
    setRevoking(id);
    try {
      await api.apiKeys.revoke(id);
      keys.reload();
    } catch (e) {
      setActionErr(e);
    } finally {
      setRevoking(null);
    }
  }

  return (
    <section>
      <h2 className="mb-1 text-base font-semibold text-slate-100">API keys</h2>
      <p className="mb-3 text-xs text-slate-500">The secret is shown only once, at creation.</p>

      <form onSubmit={create} className="card mb-4 flex flex-wrap items-end gap-3">
        <div className="min-w-[16rem] flex-1">
          <Field label="New key name" hint="A label to recognize this key, e.g. ci-runner.">
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-runner" />
          </Field>
        </div>
        <button className="btn-primary h-[34px]" disabled={busy || name.trim() === ""}>
          {busy ? "Creating…" : "Create key"}
        </button>
      </form>
      <ErrorBanner error={formErr} />

      {created && (
        <div className="card mb-4 border-emerald-800 bg-emerald-950/30">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-emerald-200">
              Key “{created.name}” created — copy it now
            </h3>
            <button className="text-xs text-slate-400 hover:text-slate-200" onClick={() => setCreated(null)}>
              Dismiss
            </button>
          </div>
          <p className="mb-2 mt-1 text-xs text-slate-400">
            This is the only time the secret is shown. Store it somewhere safe.
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded bg-ink-900 px-3 py-2 font-mono text-xs text-slate-100">
              {created.token}
            </code>
            <button className="btn-ghost" onClick={copyToken}>
              {copied ? "Copied ✓" : "Copy"}
            </button>
          </div>
        </div>
      )}

      <ErrorBanner error={actionErr} />
      <ErrorBanner error={keys.error} />

      {keys.loading ? (
        <Spinner />
      ) : !keys.data || keys.data.length === 0 ? (
        <Empty>No API keys.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Name</th>
              <th className="th">Created</th>
              <th className="th">Last used</th>
              <th className="th">Status</th>
              <th className="th"></th>
            </tr>
          }
        >
          {keys.data.map((k) => {
            const revoked = Boolean(k.revoked_at);
            return (
              <tr key={k.id}>
                <td className="td font-medium">{k.name}</td>
                <td className="td text-slate-400">{timeago(k.created_at)}</td>
                <td className="td text-slate-400">{k.last_used_at ? timeago(k.last_used_at) : "never"}</td>
                <td className="td">
                  <Badge value={revoked ? "revoked" : "active"} />
                </td>
                <td className="td text-right">
                  {revoked ? (
                    <span className="text-xs text-slate-600">—</span>
                  ) : (
                    <button
                      className="text-slate-500 hover:text-rose-300"
                      disabled={revoking === k.id}
                      onClick={() => revoke(k.id)}
                    >
                      {revoking === k.id ? "…" : "Revoke"}
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </Table>
      )}
    </section>
  );
}
