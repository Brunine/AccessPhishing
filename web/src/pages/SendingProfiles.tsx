import { useState } from "react";
import { api } from "../api/client";
import type { DeliveryChannel, TLSMode } from "../api/types";
import { useAsync } from "../hooks";
import {
  Empty,
  ErrorBanner,
  Field,
  PageHeader,
  Spinner,
  Table,
  timeago,
} from "../components/ui";

const TLS_MODES: TLSMode[] = ["starttls", "smtps", "none"];

const BLANK = {
  name: "",
  channel: "smtp" as DeliveryChannel,
  smtp_host: "",
  smtp_port: 587,
  smtp_user: "",
  smtp_pass: "",
  from_address: "",
  from_name: "",
  tls_mode: "starttls" as TLSMode,
  // SMS (Twilio)
  sms_provider: "twilio",
  sms_sender_id: "",
  api_client_id: "", // Twilio Account SID
  secret: "", // Twilio auth token (write-only)
};

export default function SendingProfiles() {
  const { data, loading, error, reload } = useAsync(() => api.profiles.list());
  const [form, setForm] = useState({ ...BLANK });
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<unknown>(null);

  const isSMS = form.channel === "sms";
  const canSubmit = isSMS
    ? Boolean(form.name && form.sms_provider && form.sms_sender_id && form.api_client_id)
    : Boolean(form.name && form.smtp_host && form.from_address);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null);
    setBusy(true);
    try {
      if (isSMS) {
        await api.profiles.create({
          name: form.name,
          channel: "sms",
          sms_provider: form.sms_provider,
          sms_sender_id: form.sms_sender_id,
          api_client_id: form.api_client_id, // Twilio Account SID
          secret: form.secret || undefined, // auth token, write-only
        });
      } else {
        await api.profiles.create({
          name: form.name,
          channel: "smtp",
          smtp_host: form.smtp_host,
          smtp_port: Number(form.smtp_port),
          smtp_user: form.smtp_user || undefined,
          smtp_pass: form.smtp_pass || undefined,
          from_address: form.from_address,
          from_name: form.from_name || undefined,
          tls_mode: form.tls_mode,
        });
      }
      setForm({ ...BLANK });
      reload();
    } catch (e) {
      setFormErr(e);
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    setFormErr(null);
    try {
      await api.profiles.remove(id);
      reload();
    } catch (e) {
      setFormErr(e);
    }
  }

  return (
    <div>
      <PageHeader
        title="Sending Profiles"
        subtitle="Delivery endpoints (email via SMTP, SMS via Twilio). Secrets (SMTP password / SMS auth token) are encrypted server-side (AES-256-GCM) and never returned — write-only."
      />

      <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <form onSubmit={create} className="card space-y-3">
          <h2 className="text-sm font-semibold text-slate-200">New profile</h2>
          <ErrorBanner error={formErr} />
          <div className="grid grid-cols-[150px_1fr] gap-3">
            <Field label="Channel">
              <select
                className="input"
                value={form.channel}
                onChange={(e) => setForm({ ...form, channel: e.target.value as DeliveryChannel })}
              >
                <option value="smtp">SMTP (email)</option>
                <option value="sms">SMS (Twilio)</option>
              </select>
            </Field>
            <Field label="Name">
              <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </Field>
          </div>

          {isSMS ? (
            <>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Provider">
                  <select className="input" value={form.sms_provider} onChange={(e) => setForm({ ...form, sms_provider: e.target.value })}>
                    <option value="twilio">twilio</option>
                  </select>
                </Field>
                <Field label="Sender ID" hint="E.164 'From' or an alphanumeric sender id.">
                  <input className="input" value={form.sms_sender_id} onChange={(e) => setForm({ ...form, sms_sender_id: e.target.value })} placeholder="+15550000000" required />
                </Field>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Account SID">
                  <input className="input" value={form.api_client_id} onChange={(e) => setForm({ ...form, api_client_id: e.target.value })} placeholder="ACxxxxxxxx" autoComplete="off" required />
                </Field>
                <Field label="Auth token (write-only)">
                  <input className="input" type="password" value={form.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} autoComplete="new-password" />
                </Field>
              </div>
            </>
          ) : (
            <>
              <div className="grid grid-cols-[1fr_120px] gap-3">
                <Field label="SMTP host">
                  <input className="input" value={form.smtp_host} onChange={(e) => setForm({ ...form, smtp_host: e.target.value })} placeholder="smtp.relay.test" required />
                </Field>
                <Field label="Port">
                  <input className="input" type="number" value={form.smtp_port} onChange={(e) => setForm({ ...form, smtp_port: Number(e.target.value) })} required />
                </Field>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="SMTP user (optional)">
                  <input className="input" value={form.smtp_user} onChange={(e) => setForm({ ...form, smtp_user: e.target.value })} autoComplete="off" />
                </Field>
                <Field label="SMTP password (write-only)">
                  <input className="input" type="password" value={form.smtp_pass} onChange={(e) => setForm({ ...form, smtp_pass: e.target.value })} autoComplete="new-password" />
                </Field>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="From address">
                  <input className="input" type="email" value={form.from_address} onChange={(e) => setForm({ ...form, from_address: e.target.value })} placeholder="it@customer.test" required />
                </Field>
                <Field label="From name (optional)">
                  <input className="input" value={form.from_name} onChange={(e) => setForm({ ...form, from_name: e.target.value })} placeholder="IT Support" />
                </Field>
              </div>
              <Field label="TLS mode">
                <select className="input" value={form.tls_mode} onChange={(e) => setForm({ ...form, tls_mode: e.target.value as TLSMode })}>
                  {TLS_MODES.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </Field>
            </>
          )}
          <button className="btn-primary" disabled={busy || !canSubmit}>
            {busy ? "Creating…" : "Create profile"}
          </button>
        </form>

        <div>
          <ErrorBanner error={error} />
          {loading ? (
            <Spinner />
          ) : !data || data.length === 0 ? (
            <Empty>No sending profiles yet.</Empty>
          ) : (
            <Table
              head={
                <tr>
                  <th className="th">Name</th>
                  <th className="th">Channel</th>
                  <th className="th">Endpoint</th>
                  <th className="th">From / Sender</th>
                  <th className="th"></th>
                </tr>
              }
            >
              {data.map((p) => (
                <tr key={p.id}>
                  <td className="td font-medium">{p.name}</td>
                  <td className="td text-slate-400">{p.channel}</td>
                  <td className="td text-slate-400">
                    {p.channel === "sms"
                      ? p.sms_provider ?? "—"
                      : `${p.smtp_host}:${p.smtp_port} · ${p.tls_mode}`}
                  </td>
                  <td className="td text-slate-400">
                    {p.channel === "sms" ? p.sms_sender_id ?? "—" : p.from_address}
                  </td>
                  <td className="td text-right">
                    <button className="text-slate-500 hover:text-rose-300" onClick={() => remove(p.id)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </Table>
          )}
          <p className="mt-3 text-xs text-slate-500">
            Last updated times reflect the stored profile. Passwords are never
            shown — to change one, recreate the profile.
          </p>
          {data && data.length > 0 && (
            <p className="mt-1 text-xs text-slate-600">
              {data.length} profile(s) · newest {timeago(data[0].created_at)}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
