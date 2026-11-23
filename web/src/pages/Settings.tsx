import { useState } from "react";
import { api } from "../api/client";
import type { CreatedAPIKey } from "../api/types";
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
    <div>
      <PageHeader
        title="Settings — API keys"
        subtitle="Operator access keys for this tenant. The secret is shown only once, at creation."
      />

      <form onSubmit={create} className="card mb-4 flex flex-wrap items-end gap-3">
        <div className="min-w-[16rem] flex-1">
          <Field label="New key name" hint="A label to recognize this key, e.g. ci-runner or my-laptop.">
            <input
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="ci-runner"
            />
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
            <h2 className="text-sm font-semibold text-emerald-200">
              Key “{created.name}” created — copy it now
            </h2>
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
    </div>
  );
}
