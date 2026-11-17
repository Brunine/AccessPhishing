import { useState } from "react";
import { api } from "../api/client";
import type { Template } from "../api/types";
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

const KINDS = ["email", "sms", "landing", "phishlet", "script", "voice"];

const BLANK = { kind: "email", name: "", subject: "", body: "" };

export default function Templates() {
  const { data, loading, error, reload } = useAsync(() => api.templates.list());
  const [form, setForm] = useState<{
    id?: string;
    kind: string;
    name: string;
    subject: string;
    body: string;
  }>({ ...BLANK });
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<unknown>(null);

  const editing = Boolean(form.id);

  function edit(t: Template) {
    setForm({
      id: t.id,
      kind: t.kind,
      name: t.name,
      subject: t.subject ?? "",
      body: t.body,
    });
    setFormErr(null);
  }
  function resetForm() {
    setForm({ ...BLANK });
    setFormErr(null);
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null);
    setBusy(true);
    try {
      const payload = {
        kind: form.kind,
        name: form.name,
        subject: form.subject || undefined,
        body: form.body,
      };
      if (form.id) await api.templates.update(form.id, payload);
      else await api.templates.create(payload);
      resetForm();
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
      await api.templates.remove(id);
      if (form.id === id) resetForm();
      reload();
    } catch (e) {
      setFormErr(e);
    }
  }

  return (
    <div>
      <PageHeader
        title="Templates"
        subtitle="Go text/template bodies. Variables: {{.first_name}}, {{.last_name}}, {{.email}}, {{.link}}."
      />

      <div className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <form onSubmit={save} className="card space-y-3">
          <h2 className="text-sm font-semibold text-slate-200">
            {editing ? "Edit template" : "New template"}
          </h2>
          <ErrorBanner error={formErr} />
          <div className="grid grid-cols-[150px_1fr] gap-3">
            <Field label="Kind">
              <select
                className="input"
                value={form.kind}
                onChange={(e) => setForm({ ...form, kind: e.target.value })}
              >
                {KINDS.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Name">
              <input
                className="input"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Q2 password reset drill"
                required
              />
            </Field>
          </div>
          <Field label="Subject">
            <input
              className="input"
              value={form.subject}
              onChange={(e) => setForm({ ...form, subject: e.target.value })}
              placeholder="Action required, {{.first_name}}"
            />
          </Field>
          <Field label="Body">
            <textarea
              className="input h-56 font-mono text-xs"
              value={form.body}
              onChange={(e) => setForm({ ...form, body: e.target.value })}
              placeholder={'<p>Hi {{.first_name}},</p>\n<p><a href="{{.link}}">Review now</a></p>'}
              required
            />
          </Field>
          <div className="flex gap-2">
            <button className="btn-primary" disabled={busy || !form.name || !form.body}>
              {busy ? "Saving…" : editing ? "Save changes" : "Create"}
            </button>
            {editing && (
              <button type="button" className="btn-ghost" onClick={resetForm}>
                Cancel
              </button>
            )}
          </div>
        </form>

        <div>
          <ErrorBanner error={error} />
          {loading ? (
            <Spinner />
          ) : !data || data.length === 0 ? (
            <Empty>No templates yet.</Empty>
          ) : (
            <Table
              head={
                <tr>
                  <th className="th">Name</th>
                  <th className="th">Kind</th>
                  <th className="th">Updated</th>
                  <th className="th"></th>
                </tr>
              }
            >
              {data.map((t) => (
                <tr key={t.id}>
                  <td className="td font-medium">{t.name}</td>
                  <td className="td text-slate-400">{t.kind}</td>
                  <td className="td text-slate-400">{timeago(t.updated_at)}</td>
                  <td className="td text-right">
                    <button className="mr-3 text-indigo-300 hover:underline" onClick={() => edit(t)}>
                      Edit
                    </button>
                    <button className="text-slate-500 hover:text-rose-300" onClick={() => remove(t.id)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </div>
      </div>
    </div>
  );
}
