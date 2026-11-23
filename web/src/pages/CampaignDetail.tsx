import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { Approval, Campaign } from "../api/types";
import { useAsync } from "../hooks";
import { FunnelChart, TimelineChart } from "../components/charts";
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

export default function CampaignDetail() {
  const { id = "" } = useParams();
  const camp = useAsync(() => api.campaigns.get(id), [id]);

  if (camp.loading) return <Spinner />;
  if (camp.error) return <ErrorBanner error={camp.error} />;
  if (!camp.data) return <Empty>Campaign not found.</Empty>;

  const c = camp.data;
  return (
    <div>
      <PageHeader
        title={c.name}
        subtitle={`Campaign ${c.id}`}
        actions={<Badge value={c.status} />}
      />
      <Link to="/campaigns" className="mb-4 inline-block text-sm text-slate-400 hover:text-slate-200">
        ← All campaigns
      </Link>

      {c.status === "draft" ? (
        <LaunchForm campaign={c} onLaunched={() => camp.reload()} />
      ) : (
        <LaunchedView campaign={c} />
      )}
    </div>
  );
}

function LaunchForm({
  campaign,
  onLaunched,
}: {
  campaign: Campaign;
  onLaunched: () => void;
}) {
  const groups = useAsync(() => api.groups.list());
  const templates = useAsync(() => api.templates.list());
  const profiles = useAsync(() => api.profiles.list());

  const [groupId, setGroupId] = useState("");
  const [templateId, setTemplateId] = useState("");
  const [profileId, setProfileId] = useState("");
  const [landing, setLanding] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  async function launch(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await api.campaigns.launch(campaign.id, {
        group_id: groupId || undefined,
        template_id: templateId || undefined,
        sending_profile_id: profileId || undefined,
        landing_url: landing || undefined,
      });
      onLaunched();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={launch} className="card max-w-2xl space-y-4">
      <h2 className="text-sm font-semibold text-slate-200">Launch campaign</h2>
      <p className="text-xs text-slate-500">
        Snapshots the selected group's contacts (suppressed addresses skipped),
        assigns the template + sending profile, and moves the campaign to
        <span className="text-amber-200"> scheduled</span>.
      </p>
      <ErrorBanner error={err} />

      <Field label="Target group">
        <select className="input" value={groupId} onChange={(e) => setGroupId(e.target.value)} required>
          <option value="">Select a group…</option>
          {(groups.data ?? []).map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
      </Field>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Template">
          <select className="input" value={templateId} onChange={(e) => setTemplateId(e.target.value)} required>
            <option value="">Select…</option>
            {(templates.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.kind})
              </option>
            ))}
          </select>
        </Field>
        <Field label="Sending profile">
          <select className="input" value={profileId} onChange={(e) => setProfileId(e.target.value)} required>
            <option value="">Select…</option>
            {(profiles.data ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                [{p.channel}] {p.name} —{" "}
                {p.channel === "sms" ? p.sms_sender_id ?? p.sms_provider : p.from_address}
              </option>
            ))}
          </select>
        </Field>
      </div>

      <Field label="Landing URL (optional)" hint="Where /t/{token} redirects on click.">
        <input className="input" value={landing} onChange={(e) => setLanding(e.target.value)} placeholder="https://portal.example.test/login" />
      </Field>

      <button className="btn-primary" disabled={busy || !groupId}>
        {busy ? "Launching…" : "Launch"}
      </button>
    </form>
  );
}

function ReportSection({ campaignId }: { campaignId: string }) {
  const [bucket, setBucket] = useState<"hour" | "day">("day");
  const [poll, setPoll] = useState(false);
  const report = useAsync(() => api.campaigns.report(campaignId, bucket), [campaignId, bucket]);
  const [csvErr, setCsvErr] = useState<unknown>(null);
  const [downloading, setDownloading] = useState(false);
  const [pdfBusy, setPdfBusy] = useState(false);

  // Bounded 30s poll (opt-in). report.reload is stable (useAsync).
  useEffect(() => {
    if (!poll) return;
    const t = setInterval(() => report.reload(), 30000);
    return () => clearInterval(t);
  }, [poll, report.reload]);

  async function exportCsv() {
    setCsvErr(null);
    setDownloading(true);
    try {
      await api.campaigns.reportCsv(campaignId);
    } catch (e) {
      setCsvErr(e);
    } finally {
      setDownloading(false);
    }
  }

  async function exportPdf() {
    setCsvErr(null);
    setPdfBusy(true);
    try {
      await api.campaigns.reportPdf(campaignId, bucket);
    } catch (e) {
      setCsvErr(e);
    } finally {
      setPdfBusy(false);
    }
  }

  return (
    <div className="card space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-200">Report</h2>
        <div className="flex items-center gap-2 text-xs">
          <div className="flex overflow-hidden rounded border border-ink-600">
            {(["hour", "day"] as const).map((b) => (
              <button
                key={b}
                className={`px-2 py-1 ${bucket === b ? "bg-ink-700 text-slate-100" : "text-slate-400 hover:text-slate-200"}`}
                onClick={() => setBucket(b)}
              >
                {b}
              </button>
            ))}
          </div>
          <label className="flex items-center gap-1 text-slate-400">
            <input type="checkbox" checked={poll} onChange={(e) => setPoll(e.target.checked)} />
            auto 30s
          </label>
          <button className="text-slate-400 hover:text-slate-200" onClick={() => report.reload()}>
            Refresh
          </button>
          <button className="btn-ghost px-2 py-1" onClick={exportCsv} disabled={downloading}>
            {downloading ? "…" : "Download CSV"}
          </button>
          <button className="btn-ghost px-2 py-1" onClick={exportPdf} disabled={pdfBusy}>
            {pdfBusy ? "…" : "Download PDF"}
          </button>
        </div>
      </div>

      <ErrorBanner error={report.error} />
      <ErrorBanner error={csvErr} />

      {report.loading && !report.data ? (
        <Spinner />
      ) : report.data ? (
        <div className="space-y-6">
          <div>
            <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
              Funnel ({report.data.totals.recipients} recipients)
            </h3>
            <FunnelChart totals={report.data.totals} />
          </div>
          <div>
            <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
              Event timeline (by {report.data.bucket})
            </h3>
            <TimelineChart timeline={report.data.timeline} />
          </div>
        </div>
      ) : (
        <Empty>No report data.</Empty>
      )}
      <p className="text-xs text-slate-600">
        The CSV export contains per-recipient state and stage timestamps only —
        no captured credentials or session material.
      </p>
    </div>
  );
}

function LaunchedView({ campaign }: { campaign: Campaign }) {
  const targets = useAsync(() => api.campaigns.targets(campaign.id), [campaign.id]);
  const links = useAsync(() => api.campaigns.links(campaign.id), [campaign.id]);
  const approvals = useAsync(() => api.approvals.list());

  const [showLinks, setShowLinks] = useState(false);
  const [sendMsg, setSendMsg] = useState<string | null>(null);
  const [sendErr, setSendErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [requesting, setRequesting] = useState(false);

  const templateApproval: Approval | undefined = (approvals.data ?? []).find(
    (a) => a.subject_type === "template" && a.subject_id === campaign.template_id
  );
  const approved = templateApproval?.status === "approved";

  async function send() {
    setSendErr(null);
    setSendMsg(null);
    setBusy(true);
    try {
      const res = await api.campaigns.send(campaign.id);
      setSendMsg(`Enqueued (${res.status}). The worker will deliver to recipients.`);
      setTimeout(() => targets.reload(), 1200);
    } catch (e) {
      setSendErr(e);
    } finally {
      setBusy(false);
    }
  }

  async function requestApproval() {
    if (!campaign.template_id) return;
    setSendErr(null);
    setRequesting(true);
    try {
      await api.approvals.request({
        subject_type: "template",
        subject_id: campaign.template_id,
      });
      approvals.reload();
    } catch (e) {
      setSendErr(e);
    } finally {
      setRequesting(false);
    }
  }

  return (
    <div className="space-y-6">
      <ReportSection campaignId={campaign.id} />

      <div className="card">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <span className="text-slate-400">
            Template:{" "}
            <span className="font-mono text-slate-300">
              {campaign.template_id ?? "—"}
            </span>
          </span>
          <span className="text-slate-400">
            Profile:{" "}
            <span className="font-mono text-slate-300">
              {campaign.sending_profile_id ?? "—"}
            </span>
          </span>
          <span className="text-slate-400">
            Approval:{" "}
            {templateApproval ? (
              <Badge value={templateApproval.status} />
            ) : (
              <span className="text-slate-500">none</span>
            )}
          </span>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button className="btn-primary" onClick={send} disabled={busy}>
            {busy ? "Sending…" : "Send campaign"}
          </button>
          {!approved && (
            <button className="btn-ghost" onClick={requestApproval} disabled={requesting || !campaign.template_id}>
              {requesting ? "Requesting…" : "Request template approval"}
            </button>
          )}
          <button className="btn-ghost" onClick={() => setShowLinks((v) => !v)}>
            {showLinks ? "Hide links" : "Show links"}
          </button>
        </div>

        {sendMsg && (
          <div className="mt-3 rounded-md border border-emerald-900 bg-emerald-950/40 px-3 py-2 text-sm text-emerald-200">
            {sendMsg}
          </div>
        )}
        <div className="mt-3">
          <ErrorBanner error={sendErr} />
        </div>
        {!approved && (
          <p className="mt-1 text-xs text-slate-500">
            Sending is gated: the template must be approved (admin) on the
            Approvals page before the API will accept a send.
          </p>
        )}
      </div>

      {showLinks && (
        <div className="card">
          <h2 className="mb-3 text-sm font-semibold text-slate-200">
            Per-recipient tracking links
          </h2>
          {links.loading ? (
            <Spinner />
          ) : !links.data || links.data.length === 0 ? (
            <Empty>No recipients.</Empty>
          ) : (
            <Table
              head={
                <tr>
                  <th className="th">Click URL</th>
                  <th className="th">Pixel URL</th>
                </tr>
              }
            >
              {links.data.map((l) => (
                <tr key={l.recipient_id}>
                  <td className="td font-mono text-xs text-indigo-300">{l.click_url}</td>
                  <td className="td font-mono text-xs text-slate-400">{l.pixel_url}</td>
                </tr>
              ))}
            </Table>
          )}
        </div>
      )}

      <div>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">
            Recipients &amp; state
          </h2>
          <button className="text-xs text-slate-400 hover:text-slate-200" onClick={() => targets.reload()}>
            Refresh
          </button>
        </div>
        <ErrorBanner error={targets.error} />
        {targets.loading ? (
          <Spinner />
        ) : !targets.data || targets.data.length === 0 ? (
          <Empty>No recipients snapshotted.</Empty>
        ) : (
          <Table
            head={
              <tr>
                <th className="th">Email</th>
                <th className="th">State</th>
                <th className="th">Last event</th>
              </tr>
            }
          >
            {targets.data.map((t) => (
              <tr key={t.contact_id}>
                <td className="td">{t.email}</td>
                <td className="td">
                  <Badge value={t.state} />
                </td>
                <td className="td text-slate-400">{timeago(t.last_event_at)}</td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    </div>
  );
}
