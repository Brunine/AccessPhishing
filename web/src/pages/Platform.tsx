import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../hooks";
import {
  Empty,
  ErrorBanner,
  PageHeader,
  Spinner,
  Table,
} from "../components/ui";

function rpct(v: number): string {
  return `${Math.round(v * 1000) / 10}%`;
}

export default function Platform() {
  const tenants = useAsync(() => api.platform.tenants());

  return (
    <div>
      <PageHeader
        title="Platform"
        subtitle="Cross-tenant oversight — headline KPIs across all tenants (admin)."
        actions={
          <button className="btn-ghost" onClick={() => tenants.reload()}>
            Refresh
          </button>
        }
      />
      <ErrorBanner error={tenants.error} />
      {tenants.loading ? (
        <Spinner />
      ) : !tenants.data || tenants.data.length === 0 ? (
        <Empty>No tenants.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Tenant</th>
              <th className="th">Slug</th>
              <th className="th text-right">Campaigns</th>
              <th className="th text-right">Recipients</th>
              <th className="th text-right">Clicked</th>
              <th className="th text-right">Creds</th>
              <th className="th"></th>
            </tr>
          }
        >
          {tenants.data.map((t) => (
            <tr key={t.tenant_id}>
              <td className="td font-medium">
                <Link className="text-indigo-300 hover:underline" to={`/platform/${t.tenant_id}`}>
                  {t.name}
                </Link>
              </td>
              <td className="td font-mono text-slate-400">{t.slug}</td>
              <td className="td text-right tabular-nums">{t.campaigns}</td>
              <td className="td text-right tabular-nums">{t.totals.recipients}</td>
              <td className="td text-right tabular-nums text-violet-300">{rpct(t.rates.clicked)}</td>
              <td className="td text-right tabular-nums text-rose-300">{rpct(t.rates.creds)}</td>
              <td className="td text-right">
                <Link className="text-slate-400 hover:text-slate-200" to={`/platform/${t.tenant_id}`}>
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
