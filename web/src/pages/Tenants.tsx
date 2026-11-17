import { useState } from "react";
import { api } from "../api/client";
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

function slugify(s: string): string {
  return s
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export default function Tenants() {
  const { data, loading, error, reload } = useAsync(() => api.tenants.list());
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<unknown>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null);
    setBusy(true);
    try {
      await api.tenants.create({ name, slug: slug || slugify(name) });
      setName("");
      setSlug("");
      setSlugTouched(false);
      reload();
    } catch (e) {
      setFormErr(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Tenants"
        subtitle="Customer workspaces. Platform-level; admin only."
      />

      <form onSubmit={create} className="card mb-6 grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
        <Field label="Name">
          <input
            className="input"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              if (!slugTouched) setSlug(slugify(e.target.value));
            }}
            placeholder="Acme Corp"
          />
        </Field>
        <Field label="Slug">
          <input
            className="input font-mono"
            value={slug}
            onChange={(e) => {
              setSlug(e.target.value);
              setSlugTouched(true);
            }}
            placeholder="acme-corp"
          />
        </Field>
        <button className="btn-primary h-[34px]" disabled={busy || !name}>
          {busy ? "Creating…" : "Create tenant"}
        </button>
        <div className="sm:col-span-3">
          <ErrorBanner error={formErr} />
        </div>
      </form>

      <ErrorBanner error={error} />
      {loading ? (
        <Spinner />
      ) : !data || data.length === 0 ? (
        <Empty>No tenants yet.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Name</th>
              <th className="th">Slug</th>
              <th className="th">Status</th>
              <th className="th">Created</th>
            </tr>
          }
        >
          {data.map((t) => (
            <tr key={t.id}>
              <td className="td font-medium">{t.name}</td>
              <td className="td font-mono text-slate-400">{t.slug}</td>
              <td className="td">
                <Badge value={t.status} />
              </td>
              <td className="td text-slate-400">{timeago(t.created_at)}</td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}
