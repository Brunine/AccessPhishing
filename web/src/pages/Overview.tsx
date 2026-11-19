import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { TenantSummary } from "../api/types";
import { useAsync } from "../hooks";
import { RateBar } from "../components/charts";
import {
  Badge,
  Empty,
  ErrorBanner,
  PageHeader,
  Spinner,
  Table,
} from "../components/ui";

function rpct(v: number): string {
  return `${Math.round(v * 1000) / 10}%`;
}

export default function Overview() {
  // Operators are tenant-scoped, so any campaign carries the caller's tenant id.
  const camps = useAsync(() => api.campaigns.list());
  const tenantId = camps.data && camps.data.length > 0 ? camps.data[0].tenant_id : undefined;
  const summary = useAsync<TenantSummary | null>(
    () => (tenantId ? api.tenants.summary(tenantId) : Promise.resolve(null)),
    [tenantId]
  );

  const [pdfBusy, setPdfBusy] = useState(false);
  const [pdfErr, setPdfErr] = useState<unknown>(null);

  async function exportPdf() {
    if (!tenantId) return;
    setPdfErr(null);
    setPdfBusy(true);
    try {
      await api.tenants.summaryPdf(tenantId);
    } catch (e) {
      setPdfErr(e);
    } finally {
      setPdfBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Overview"
        subtitle="Portfolio-wide funnel rates across your campaigns."
        actions={
          <>
            <button
              className="btn-ghost"
              onClick={exportPdf}
              disabled={pdfBusy || !tenantId}
            >
              {pdfBusy ? "Preparing…" : "Download executive summary"}
            </button>
            <button
              className="btn-ghost"
              onClick={() => {
                camps.reload();
                summary.reload();
              }}
            >
              Refresh
            </button>
          </>
        }
      />

      <ErrorBanner error={camps.error} />
      <ErrorBanner error={summary.error} />
      <ErrorBanner error={pdfErr} />

      {camps.loading || summary.loading ? (
        <Spinner />
      ) : !summary.data || summary.data.campaigns.length === 0 ? (
        <Empty>No campaigns yet.</Empty>
      ) : (
        <div className="space-y-6">
          <div className="card">
            <h2 className="mb-3 text-sm font-semibold text-slate-200">
              Aggregate rates ({summary.data.totals.recipients} recipients across{" "}
              {summary.data.campaigns.length} campaigns)
            </h2>
            <div className="max-w-xl space-y-2">
              <RateBar label="Delivered" value={summary.data.rates.delivered} color="#0ea5e9" />
              <RateBar label="Opened" value={summary.data.rates.opened} color="#818cf8" />
              <RateBar label="Clicked" value={summary.data.rates.clicked} color="#a78bfa" />
              <RateBar label="Submitted creds" value={summary.data.rates.creds} color="#fb7185" />
              <RateBar label="Session hijacked" value={summary.data.rates.session_hijacked} color="#f43f5e" />
            </div>
          </div>

          <Table
            head={
              <tr>
                <th className="th">Campaign</th>
                <th className="th">Status</th>
                <th className="th text-right">Recipients</th>
                <th className="th text-right">Delivered</th>
                <th className="th text-right">Opened</th>
                <th className="th text-right">Clicked</th>
                <th className="th text-right">Creds</th>
              </tr>
            }
          >
            {summary.data.campaigns.map((c) => (
              <tr key={c.campaign_id}>
                <td className="td font-medium">
                  <Link className="text-indigo-300 hover:underline" to={`/campaigns/${c.campaign_id}`}>
                    {c.name}
                  </Link>
                </td>
                <td className="td">
                  <Badge value={c.status} />
                </td>
                <td className="td text-right tabular-nums">{c.totals.recipients}</td>
                <td className="td text-right tabular-nums text-slate-300">{rpct(c.rates.delivered)}</td>
                <td className="td text-right tabular-nums text-slate-300">{rpct(c.rates.opened)}</td>
                <td className="td text-right tabular-nums text-violet-300">{rpct(c.rates.clicked)}</td>
                <td className="td text-right tabular-nums text-rose-300">{rpct(c.rates.creds)}</td>
              </tr>
            ))}
          </Table>
        </div>
      )}
    </div>
  );
}
