import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../hooks";
import {
  Badge,
  Empty,
  ErrorBanner,
  PageHeader,
  Spinner,
  Table,
  timeago,
} from "../components/ui";

export default function Campaigns() {
  const { data, loading, error, reload } = useAsync(() => api.campaigns.list());
  const engagements = useAsync(() => api.engagements.list());
  const [name, setName] = useState("");
  const [channel, setChannel] = useState("email");
  const [engagementId, setEngagementId] = useState("");
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<unknown>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null);
    setBusy(true);
    try {
      await api.campaigns.create({
        name,
        channel,
        engagement_id: engagementId || undefined,
      });
      setName("");
      setChannel("email");
      setEngagementId("");
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
        title="Campaigns"
        subtitle="Create a campaign, then open it to launch, approve, and send."
      />

      <form onSubmit={create} className="card mb-6 flex flex-wrap gap-2">
        <input
          className="input flex-1"
          placeholder="New campaign name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <select
          className="input w-full sm:w-44"
          value={channel}
          onChange={(e) => setChannel(e.target.value)}
          title="Delivery vector"
        >
          <option value="email">Email</option>
          <option value="qr">QR / quishing</option>
        </select>
        <select
          className="input w-full sm:w-72"
          value={engagementId}
          onChange={(e) => setEngagementId(e.target.value)}
          title="Authorizing engagement (required before the campaign can launch)"
        >
          <option value="">Engagement (optional now, required to launch)…</option>
          {(engagements.data ?? []).map((en) => (
            <option key={en.id} value={en.id}>
              {en.name} — {en.client_name} [{en.effective_status}]
            </option>
          ))}
        </select>
        <button className="btn-primary" disabled={busy || !name}>
          {busy ? "Creating…" : "Create"}
        </button>
      </form>
      <ErrorBanner error={formErr} />
      <ErrorBanner error={error} />

      {loading ? (
        <Spinner />
      ) : !data || data.length === 0 ? (
        <Empty>No campaigns yet.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Name</th>
              <th className="th">Channel</th>
              <th className="th">Status</th>
              <th className="th">Created</th>
              <th className="th"></th>
            </tr>
          }
        >
          {data.map((c) => (
            <tr key={c.id}>
              <td className="td font-medium">
                <Link className="text-indigo-300 hover:underline" to={`/campaigns/${c.id}`}>
                  {c.name}
                </Link>
              </td>
              <td className="td text-slate-400">{c.channel === "qr" ? "QR" : "email"}</td>
              <td className="td">
                <Badge value={c.status} />
              </td>
              <td className="td text-slate-400">{timeago(c.created_at)}</td>
              <td className="td text-right">
                <Link className="text-slate-400 hover:text-slate-200" to={`/campaigns/${c.id}`}>
                  Open →
                </Link>
              </td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}
