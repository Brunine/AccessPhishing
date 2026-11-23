import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
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

export default function PlatformTenant() {
  const { id = "" } = useParams();
  const summary = useAsync(() => api.platform.summary(id), [id]);
  const [pdfBusy, setPdfBusy] = useState(false);
  const [pdfErr, setPdfErr] = useState<unknown>(null);

  async function exportPdf() {
    setPdfErr(null);
    setPdfBusy(true);
    try {
      await api.platform.summaryPdf(id);
    } catch (e) {
      setPdfErr(e);
    } finally {
      setPdfBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Tenant report"
        subtitle={`Tenant ${id}`}
        actions={
          <button className="btn-ghost" onClick={exportPdf} disabled={pdfBusy}>
            {pdfBusy ? "Preparing…" : "Download executive summary"}
          </button>
        }
      />
      <Link to="/platform" className="mb-4 inline-block text-sm text-slate-400 hover:text-slate-200">
        ← All tenants
      </Link>

      <ErrorBanner error={summary.error} />
      <ErrorBanner error={pdfErr} />

      {summary.loading ? (
        <Spinner />
      ) : !summary.data ? (
        <Empty>No data.</Empty>
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

          {summary.data.campaigns.length === 0 ? (
            <Empty>No campaigns.</Empty>
          ) : (
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
                  <td className="td font-medium">{c.name}</td>
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
          )}
        </div>
      )}
    </div>
  );
}
