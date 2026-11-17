import { useState } from "react";
import { api } from "../api/client";
import type { Contact, Group, ImportResult } from "../api/types";
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

// parseCSV reads a header row (email,first_name,last_name,phone in any order)
// and returns one object per data row. Commas only; quoted fields not required
// for the simple operator import path.
function parseCSV(text: string): Partial<Contact>[] {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  if (lines.length === 0) return [];
  const header = lines[0].split(",").map((h) => h.trim().toLowerCase());
  const hasHeader = header.includes("email");
  const cols = hasHeader ? header : ["email", "first_name", "last_name", "phone"];
  const rows = hasHeader ? lines.slice(1) : lines;
  return rows.map((line) => {
    const cells = line.split(",").map((c) => c.trim());
    const obj: Partial<Contact> = {};
    cols.forEach((c, i) => {
      const v = cells[i];
      if (!v) return;
      if (c === "email") obj.email = v;
      else if (c === "first_name" || c === "firstname") obj.first_name = v;
      else if (c === "last_name" || c === "lastname") obj.last_name = v;
      else if (c === "phone") obj.phone = v;
    });
    return obj;
  });
}

export default function Contacts() {
  const groups = useAsync(() => api.groups.list());
  const [groupFilter, setGroupFilter] = useState<string>("");
  const contacts = useAsync(
    () => api.contacts.list(groupFilter || undefined),
    [groupFilter]
  );

  return (
    <div>
      <PageHeader
        title="Contacts & Groups"
        subtitle="Targets and their groupings. Bulk import is suppression-aware."
      />
      <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
        <div className="space-y-6">
          <GroupsPanel
            onChange={() => {
              groups.reload();
              contacts.reload();
            }}
            groupsState={groups}
            filter={groupFilter}
            setFilter={setGroupFilter}
          />
          <ImportPanel
            groups={groups.data ?? []}
            onDone={() => contacts.reload()}
          />
        </div>
        <ContactsPanel
          state={contacts}
          groups={groups.data ?? []}
          reloadGroups={() => groups.reload()}
        />
      </div>
    </div>
  );
}

function GroupsPanel({
  groupsState,
  onChange,
  filter,
  setFilter,
}: {
  groupsState: ReturnType<typeof useAsync<Group[]>>;
  onChange: () => void;
  filter: string;
  setFilter: (v: string) => void;
}) {
  const [name, setName] = useState("");
  const [err, setErr] = useState<unknown>(null);
  const data = groupsState.data ?? [];

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    try {
      await api.groups.create({ name });
      setName("");
      onChange();
    } catch (e) {
      setErr(e);
    }
  }
  async function remove(id: string) {
    setErr(null);
    try {
      await api.groups.remove(id);
      if (filter === id) setFilter("");
      onChange();
    } catch (e) {
      setErr(e);
    }
  }

  return (
    <div className="card">
      <h2 className="mb-3 text-sm font-semibold text-slate-200">Groups</h2>
      <ErrorBanner error={err} />
      <form onSubmit={create} className="mb-3 flex gap-2">
        <input
          className="input"
          placeholder="New group name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button className="btn-primary" disabled={!name}>
          Add
        </button>
      </form>
      <ul className="space-y-1 text-sm">
        <li>
          <button
            className={`w-full rounded px-2 py-1 text-left ${
              filter === "" ? "bg-ink-700 text-slate-100" : "text-slate-400 hover:bg-ink-700"
            }`}
            onClick={() => setFilter("")}
          >
            All contacts
          </button>
        </li>
        {data.map((g) => (
          <li key={g.id} className="flex items-center gap-1">
            <button
              className={`flex-1 rounded px-2 py-1 text-left ${
                filter === g.id ? "bg-ink-700 text-slate-100" : "text-slate-300 hover:bg-ink-700"
              }`}
              onClick={() => setFilter(g.id)}
            >
              {g.name}
            </button>
            <button
              className="px-2 text-slate-500 hover:text-rose-300"
              title="Delete group"
              onClick={() => remove(g.id)}
            >
              ✕
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ContactsPanel({
  state,
  groups,
  reloadGroups,
}: {
  state: ReturnType<typeof useAsync<Contact[]>>;
  groups: { id: string; name: string }[];
  reloadGroups: () => void;
}) {
  const [form, setForm] = useState<Partial<Contact>>({});
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await api.contacts.create({
        email: form.email,
        first_name: form.first_name,
        last_name: form.last_name,
        phone: form.phone,
        group_id: form.group_id || undefined,
      });
      setForm({});
      state.reload();
      reloadGroups();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }
  async function remove(id: string) {
    setErr(null);
    try {
      await api.contacts.remove(id);
      state.reload();
    } catch (e) {
      setErr(e);
    }
  }

  const groupName = (id?: string) =>
    id ? groups.find((g) => g.id === id)?.name ?? "—" : "—";

  return (
    <div>
      <form
        onSubmit={create}
        className="card mb-4 grid gap-3 sm:grid-cols-[1.5fr_1fr_1fr_1fr_auto] sm:items-end"
      >
        <Field label="Email">
          <input
            className="input"
            type="email"
            required
            value={form.email ?? ""}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            placeholder="user@customer.test"
          />
        </Field>
        <Field label="First">
          <input
            className="input"
            value={form.first_name ?? ""}
            onChange={(e) => setForm({ ...form, first_name: e.target.value })}
          />
        </Field>
        <Field label="Last">
          <input
            className="input"
            value={form.last_name ?? ""}
            onChange={(e) => setForm({ ...form, last_name: e.target.value })}
          />
        </Field>
        <Field label="Group">
          <select
            className="input"
            value={form.group_id ?? ""}
            onChange={(e) => setForm({ ...form, group_id: e.target.value })}
          >
            <option value="">—</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </Field>
        <button className="btn-primary h-[34px]" disabled={busy || !form.email}>
          Add
        </button>
      </form>

      <ErrorBanner error={err} />
      <ErrorBanner error={state.error} />
      {state.loading ? (
        <Spinner />
      ) : !state.data || state.data.length === 0 ? (
        <Empty>No contacts in this view.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Email</th>
              <th className="th">Name</th>
              <th className="th">Group</th>
              <th className="th">Added</th>
              <th className="th"></th>
            </tr>
          }
        >
          {state.data.map((c) => (
            <tr key={c.id}>
              <td className="td">{c.email}</td>
              <td className="td text-slate-300">
                {[c.first_name, c.last_name].filter(Boolean).join(" ") || "—"}
              </td>
              <td className="td text-slate-400">{groupName(c.group_id)}</td>
              <td className="td text-slate-400">{timeago(c.created_at)}</td>
              <td className="td text-right">
                <button
                  className="text-slate-500 hover:text-rose-300"
                  onClick={() => remove(c.id)}
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}

function ImportPanel({
  groups,
  onDone,
}: {
  groups: { id: string; name: string }[];
  onDone: () => void;
}) {
  const [text, setText] = useState("");
  const [groupId, setGroupId] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function doImport() {
    setErr(null);
    setResult(null);
    const rows = parseCSV(text).filter((r) => r.email);
    if (rows.length === 0) {
      setErr(new Error("No rows with an email column found."));
      return;
    }
    setBusy(true);
    try {
      const res = await api.contacts.import(rows, groupId || undefined);
      setResult(res);
      onDone();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    f.text().then(setText);
  }

  return (
    <div className="card">
      <h2 className="mb-1 text-sm font-semibold text-slate-200">CSV import</h2>
      <p className="mb-3 text-xs text-slate-500">
        Header row <code>email,first_name,last_name,phone</code>. Suppressed and
        duplicate addresses are skipped.
      </p>
      <ErrorBanner error={err} />
      <textarea
        className="input mb-2 h-28 font-mono text-xs"
        placeholder="email,first_name,last_name&#10;ceo@customer.test,Dana,Lee"
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <input type="file" accept=".csv,text/csv" onChange={onFile} className="mb-2 block text-xs text-slate-400" />
      <Field label="Assign to group (optional)">
        <select
          className="input"
          value={groupId}
          onChange={(e) => setGroupId(e.target.value)}
        >
          <option value="">—</option>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
      </Field>
      <button className="btn-primary mt-3 w-full" onClick={doImport} disabled={busy || !text.trim()}>
        {busy ? "Importing…" : "Import"}
      </button>
      {result && (
        <div className="mt-3 rounded-md border border-emerald-900 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-200">
          Imported {result.created} · {result.duplicates} duplicate ·{" "}
          {result.suppressed} suppressed
        </div>
      )}
    </div>
  );
}
