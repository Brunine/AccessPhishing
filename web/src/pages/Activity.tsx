import { api } from "../api/client";
import { useAsync } from "../hooks";
import {
  Badge,
  Empty,
  ErrorBanner,
  PageHeader,
  Spinner,
} from "../components/ui";

export default function Activity() {
  const { data, loading, error, reload } = useAsync(() => api.activity(50));

  return (
    <div>
      <PageHeader
        title="Activity"
        subtitle="Recent operator actions (audit log) and victim-state events for this tenant."
        actions={
          <button className="btn-ghost" onClick={reload}>
            Refresh
          </button>
        }
      />
      <ErrorBanner error={error} />
      {loading ? (
        <Spinner />
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          <div>
            <h2 className="mb-3 text-sm font-semibold text-slate-200">
              Audit log
            </h2>
            {!data || data.audit.length === 0 ? (
              <Empty>No audit entries.</Empty>
            ) : (
              <ul className="space-y-2">
                {data.audit.map((a) => (
                  <li key={a.id} className="card py-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-sm text-indigo-300">
                        {a.action}
                      </span>
                      <span className="text-xs text-slate-500">
                        {new Date(a.created_at).toLocaleString()}
                      </span>
                    </div>
                    <div className="mt-0.5 text-xs text-slate-400">
                      {a.actor_email ?? "system"}
                      {a.target_type ? ` · ${a.target_type}` : ""}
                      {a.target_id ? ` ${a.target_id.slice(0, 8)}…` : ""}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div>
            <h2 className="mb-3 text-sm font-semibold text-slate-200">
              Events
            </h2>
            {!data || data.events.length === 0 ? (
              <Empty>No events yet.</Empty>
            ) : (
              <ul className="space-y-2">
                {data.events.map((e) => (
                  <li key={e.id} className="card flex items-center justify-between gap-2 py-2">
                    <div className="flex items-center gap-2">
                      <Badge value={e.type} />
                      <span className="font-mono text-xs text-slate-500">
                        {e.campaign_id.slice(0, 8)}…
                      </span>
                    </div>
                    <span className="text-xs text-slate-500">
                      {new Date(e.occurred_at).toLocaleString()}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
