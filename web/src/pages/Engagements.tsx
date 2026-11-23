import { useState } from "react";
import { api } from "../api/client";
import { useSession } from "../auth";
import { useAsync } from "../hooks";
import type { Engagement, EngagementInput } from "../api/types";
import {
  Badge,
  Empty,
  ErrorBanner,
  Field,
  PageHeader,
  Spinner,
  Table,
} from "../components/ui";

// toISO converts a datetime-local value ("2026-12-31T23:59") to an RFC 3339
// instant, or null when empty.
function toISO(v: string): string | null {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

function fmtDate(iso?: string): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export default function Engagements() {
  const { isAdmin } = useSession();
  const { data, loading, error, reload } = useAsync(() => api.engagements.list());

  // create form
  const [name, setName] = useState("");
  const [client, setClient] = useState("");
  const [scope, setScope] = useState("");
  const [expires, setExpires] = useState("");
  const [roe, setRoe] = useState("");
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<unknown>(null);

  // per-row action state
  const [actionErr, setActionErr] = useState<unknown>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null);
    setBusy(true);
    try {
      const body: EngagementInput = {
        name,
        client_name: client,
        roe_reference: roe || null,
        authorized_scope: scope
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
        expires_at: toISO(expires),
      };
      await api.engagements.create(body);
      setName("");
      setClient("");
      setScope("");
      setExpires("");
      setRoe("");
      reload();
    } catch (e) {
      setFormErr(e);
    } finally {
      setBusy(false);
    }
  }

  async function act(
    e: Engagement,
    kind: "request" | "authorize" | "terminate"
  ) {
    setActionErr(null);
    setBusyId(e.id);
    try {
      if (kind === "request") await api.engagements.requestAuthorization(e.id);
      else if (kind === "authorize") await api.engagements.authorize(e.id);
      else await api.engagements.terminate(e.id);
      reload();
    } catch (err) {
      setActionErr(err);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <PageHeader
        title="Engagements"
        subtitle="Authorization container for campaigns. A campaign must be bound to an authorized, unexpired engagement before it can launch or send."
      />

      <form onSubmit={create} className="card mb-6 space-y-4">
        <h2 className="text-sm font-semibold text-slate-200">New engagement</h2>
        <ErrorBanner error={formErr} />
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name">
            <input
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Q1 Acme Test"
            />
          </Field>
          <Field label="Client">
            <input
              className="input"
              value={client}
              onChange={(e) => setClient(e.target.value)}
              placeholder="Acme Inc"
            />
          </Field>
        </div>
        <Field
          label="Authorized scope"
          hint="One URL or domain per line, e.g. *.acme.com or https://acme.com"
        >
          <textarea
            className="input font-mono"
            rows={3}
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder={"*.acme.com\nhttps://portal.acme.com"}
          />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Expires at (optional)">
            <input
              className="input"
              type="datetime-local"
              value={expires}
              onChange={(e) => setExpires(e.target.value)}
            />
          </Field>
          <Field label="RoE reference (optional)">
            <input
              className="input"
              value={roe}
              onChange={(e) => setRoe(e.target.value)}
              placeholder="RoE doc id / URL"
            />
          </Field>
        </div>
        <button className="btn-primary" disabled={busy || !name || !client}>
          {busy ? "Creating…" : "Create engagement"}
        </button>
      </form>

      <ErrorBanner error={actionErr} />
      <ErrorBanner error={error} />

      {loading ? (
        <Spinner />
      ) : !data || data.length === 0 ? (
        <Empty>No engagements yet.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Name</th>
              <th className="th">Client</th>
              <th className="th">Status</th>
              <th className="th">Authorized</th>
              <th className="th">Expires</th>
              <th className="th"></th>
            </tr>
          }
        >
          {data.map((e) => {
            const canRequest = e.status === "draft" || e.status === "pending_authorization";
            const canAuthorize = e.status === "pending_authorization";
            const canTerminate = e.status !== "terminated";
            return (
              <tr key={e.id}>
                <td className="td font-medium text-slate-200">{e.name}</td>
                <td className="td text-slate-400">{e.client_name}</td>
                <td className="td">
                  <Badge value={e.effective_status} />
                </td>
                <td className="td text-slate-400">{fmtDate(e.authorized_at)}</td>
                <td className="td text-slate-400">{fmtDate(e.expires_at)}</td>
                <td className="td text-right">
                  <div className="flex justify-end gap-2">
                    {canRequest && (
                      <button
                        className="btn-ghost px-2 py-1 text-xs"
                        disabled={busyId === e.id}
                        onClick={() => act(e, "request")}
                      >
                        Request auth
                      </button>
                    )}
                    {canAuthorize && (
                      <button
                        className="btn-primary px-2 py-1 text-xs"
                        disabled={!isAdmin || busyId === e.id}
                        title={isAdmin ? "Authorize" : "Admin only"}
                        onClick={() => act(e, "authorize")}
                      >
                        Authorize
                      </button>
                    )}
                    {canTerminate && (
                      <button
                        className="btn-danger px-2 py-1 text-xs"
                        disabled={!isAdmin || busyId === e.id}
                        title={isAdmin ? "Terminate (emergency stop)" : "Admin only"}
                        onClick={() => act(e, "terminate")}
                      >
                        Terminate
                      </button>
                    )}
                    {e.status === "terminated" && (
                      <span className="text-xs text-slate-500">terminal</span>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </Table>
      )}
      {!isAdmin && (
        <p className="mt-3 text-xs text-slate-500">
          You are signed in as a non-admin; authorize/terminate are admin-only
          and disabled. You can create engagements and request authorization.
        </p>
      )}
    </div>
  );
}
