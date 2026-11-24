import { useState } from "react";
import { api } from "../api/client";
import { useSession } from "../auth";
import { useAsync } from "../hooks";
import type {
  Domain,
  DomainDiagnostics,
  DomainInput,
  DomainVerificationChallenge,
  DomainVerificationCheck,
  Engagement,
} from "../api/types";
import {
  Badge,
  Empty,
  ErrorBanner,
  Field,
  PageHeader,
  Spinner,
  Table,
} from "../components/ui";

function toISO(v: string): string | null {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

function fmtDate(iso?: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

// Copyable renders a monospace value with a copy-to-clipboard button.
function Copyable({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <div className="flex items-center gap-2">
      <code className="flex-1 break-all rounded bg-ink-900 px-2 py-1 text-xs text-slate-200">
        {value}
      </code>
      <button
        type="button"
        className="btn-ghost shrink-0 px-2 py-1 text-xs"
        onClick={copy}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

export default function Domains() {
  const { isAdmin } = useSession();
  const { data, loading, error, reload } = useAsync(() => api.domains.list());
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // create form
  const [name, setName] = useState("");
  const [registrar, setRegistrar] = useState("");
  const [status, setStatus] =
    useState<NonNullable<DomainInput["status"]>>("pending_verification");
  const [expires, setExpires] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<unknown>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null);
    setBusy(true);
    try {
      const body: DomainInput = {
        name: name.trim().toLowerCase(),
        registrar: registrar || null,
        status,
        expires_at: toISO(expires),
        notes: notes || null,
      };
      await api.domains.create(body);
      setName("");
      setRegistrar("");
      setStatus("pending_verification");
      setExpires("");
      setNotes("");
      reload();
    } catch (err) {
      setFormErr(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Domains"
        subtitle="Inventory of externally purchased domains. Ownership (TXT verification) and authorization (engagement assignment) are enforced independently before a domain can be activated."
      />

      <form onSubmit={create} className="card mb-6 space-y-4">
        <h2 className="text-sm font-semibold text-slate-200">New domain</h2>
        <ErrorBanner error={formErr} />
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" hint="Lowercase bare domain, e.g. phish-target.example">
            <input
              className="input font-mono"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="phish-target.example"
            />
          </Field>
          <Field label="Registrar (optional)">
            <input
              className="input"
              value={registrar}
              onChange={(e) => setRegistrar(e.target.value)}
              placeholder="namecheap"
            />
          </Field>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Initial status">
            <select
              className="input"
              value={status}
              onChange={(e) =>
                setStatus(e.target.value as NonNullable<DomainInput["status"]>)
              }
            >
              <option value="candidate">candidate</option>
              <option value="pending_purchase">pending_purchase</option>
              <option value="pending_verification">pending_verification</option>
            </select>
          </Field>
          <Field label="Expires at (optional)">
            <input
              className="input"
              type="datetime-local"
              value={expires}
              onChange={(e) => setExpires(e.target.value)}
            />
          </Field>
        </div>
        <Field label="Notes (optional)">
          <textarea
            className="input"
            rows={2}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </Field>
        <button className="btn-primary" disabled={busy || !name.trim()}>
          {busy ? "Importing…" : "Import domain"}
        </button>
      </form>

      <ErrorBanner error={error} />

      {loading ? (
        <Spinner />
      ) : !data || data.length === 0 ? (
        <Empty>No domains yet.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Name</th>
              <th className="th">Registrar</th>
              <th className="th">Status</th>
              <th className="th">Expires</th>
              <th className="th">Notes</th>
              <th className="th"></th>
            </tr>
          }
        >
          {data.map((d) => (
            <tr key={d.id}>
              <td className="td font-mono font-medium text-slate-200">
                {d.name}
              </td>
              <td className="td text-slate-400">{d.registrar || "—"}</td>
              <td className="td">
                <Badge value={d.status} />
              </td>
              <td className="td text-slate-400">{fmtDate(d.expires_at)}</td>
              <td className="td max-w-xs truncate text-slate-400">
                {d.notes || "—"}
              </td>
              <td className="td text-right">
                <button
                  className="btn-ghost px-2 py-1 text-xs"
                  onClick={() =>
                    setSelectedId(selectedId === d.id ? null : d.id)
                  }
                >
                  {selectedId === d.id ? "Close" : "Manage"}
                </button>
              </td>
            </tr>
          ))}
        </Table>
      )}

      {selectedId && (
        <DomainDetail
          key={selectedId}
          id={selectedId}
          isAdmin={isAdmin}
          onChanged={reload}
          onClose={() => setSelectedId(null)}
        />
      )}

      {!isAdmin && (
        <p className="mt-3 text-xs text-slate-500">
          You are signed in as a non-admin; authorize/revoke and
          activate/suspend/retire are admin-only and disabled. You can import
          domains, run verification, and attach them to engagements.
        </p>
      )}
    </div>
  );
}

function DomainDetail({
  id,
  isAdmin,
  onChanged,
  onClose,
}: {
  id: string;
  isAdmin: boolean;
  onChanged: () => void;
  onClose: () => void;
}) {
  const { data: domain, loading, error, reload } = useAsync(
    () => api.domains.get(id),
    [id]
  );

  if (loading) return <div className="card mt-4"><Spinner /></div>;
  if (error || !domain)
    return (
      <div className="card mt-4">
        <ErrorBanner error={error ?? "Not found"} />
      </div>
    );

  return (
    <div className="card mt-4 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="font-mono text-base font-semibold text-slate-100">
            {domain.name}
          </h2>
          <div className="mt-1 flex items-center gap-2">
            <Badge value={domain.status} />
            <span className="text-xs text-slate-500">
              updated {fmtDate(domain.updated_at)}
            </span>
          </div>
        </div>
        <button className="btn-ghost px-2 py-1 text-xs" onClick={onClose}>
          Close
        </button>
      </div>

      <VerificationPanel domain={domain} />
      <AssignmentsPanel
        domain={domain}
        isAdmin={isAdmin}
        onChanged={() => {
          reload();
          onChanged();
        }}
      />
      <LifecyclePanel
        domain={domain}
        isAdmin={isAdmin}
        onChanged={() => {
          reload();
          onChanged();
        }}
      />
      <DiagnosticsPanel id={domain.id} />
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="border-t border-ink-700 pt-5">
      <h3 className="mb-3 text-sm font-semibold text-slate-200">{title}</h3>
      {children}
    </section>
  );
}

function VerificationPanel({ domain }: { domain: Domain }) {
  const [challenge, setChallenge] =
    useState<DomainVerificationChallenge | null>(null);
  const [checkResult, setCheckResult] =
    useState<DomainVerificationCheck | null>(null);
  const [busy, setBusy] = useState<"new" | "check" | null>(null);
  const [err, setErr] = useState<unknown>(null);

  async function newChallenge() {
    setErr(null);
    setCheckResult(null);
    setBusy("new");
    try {
      setChallenge(await api.domains.createVerification(domain.id));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(null);
    }
  }

  async function check() {
    if (!challenge) return;
    setErr(null);
    setBusy("check");
    try {
      setCheckResult(await api.domains.checkVerification(domain.id, challenge.id));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(null);
    }
  }

  const canVerify = domain.status === "pending_verification";

  return (
    <Section title="Ownership verification (TXT)">
      <ErrorBanner error={err} />
      {!canVerify && !challenge && (
        <p className="mb-3 text-xs text-slate-500">
          A TXT challenge can be issued only while the domain is
          <code className="mx-1">pending_verification</code>
          (current: <code>{domain.status}</code>).
        </p>
      )}
      <div className="mb-3 flex gap-2">
        <button
          className="btn-ghost px-3 py-1.5 text-sm"
          disabled={busy !== null || !canVerify}
          onClick={newChallenge}
        >
          {busy === "new" ? "Issuing…" : "New verification"}
        </button>
        <button
          className="btn-primary px-3 py-1.5 text-sm"
          disabled={busy !== null || !challenge}
          onClick={check}
          title={challenge ? "Check published TXT" : "Issue a challenge first"}
        >
          {busy === "check" ? "Checking…" : "Check now"}
        </button>
      </div>

      {challenge ? (
        <div className="space-y-3 rounded-md border border-ink-700 bg-ink-900/40 p-3">
          <div>
            <span className="label">Hostname</span>
            <Copyable value={challenge.hostname} />
          </div>
          <div>
            <span className="label">TXT record</span>
            <Copyable value={challenge.txt_record} />
          </div>
          <p className="text-xs text-slate-500">
            Publish this TXT record at the hostname above, then click “Check
            now”. Pending challenges are not listed by the API — this panel
            shows the one issued in this session.
          </p>
        </div>
      ) : (
        <p className="text-xs text-slate-500">
          No active challenge in this session.
        </p>
      )}

      {checkResult && (
        <div className="mt-3 rounded-md border border-ink-700 bg-ink-900/40 p-3 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Result:</span>
            <Badge value={checkResult.verified ? "verified" : "failed"} />
          </div>
          {checkResult.lookup_error && (
            <p className="mt-2 text-xs text-rose-300">
              Lookup error: {checkResult.lookup_error}
            </p>
          )}
          {!checkResult.verified &&
            checkResult.txt_records &&
            checkResult.txt_records.length > 0 && (
              <div className="mt-2">
                <span className="label">TXT records found</span>
                <ul className="mt-1 space-y-1">
                  {checkResult.txt_records.map((t, i) => (
                    <li key={i}>
                      <code className="break-all text-xs text-slate-300">
                        {t}
                      </code>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          {!checkResult.verified &&
            (!checkResult.txt_records ||
              checkResult.txt_records.length === 0) &&
            !checkResult.lookup_error && (
              <p className="mt-2 text-xs text-slate-500">
                No TXT records found at the hostname.
              </p>
            )}
        </div>
      )}
    </Section>
  );
}

function AssignmentsPanel({
  domain,
  isAdmin,
  onChanged,
}: {
  domain: Domain;
  isAdmin: boolean;
  onChanged: () => void;
}) {
  const { data: assignments, loading, error, reload } = useAsync(
    () => api.domains.assignments(domain.id),
    [domain.id]
  );
  const { data: engagements } = useAsync(() => api.engagements.list(), []);

  const [engagementId, setEngagementId] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actErr, setActErr] = useState<unknown>(null);

  // Only authorized/active engagements can receive an assignment.
  const assignable = (engagements ?? []).filter(
    (e: Engagement) =>
      e.effective_status === "authorized" || e.effective_status === "active"
  );
  const engagementName = (eid: string) =>
    (engagements ?? []).find((e) => e.id === eid)?.name ?? eid;

  const canAssign =
    domain.status === "verified" ||
    domain.status === "authorized" ||
    domain.status === "active";

  async function assign(e: React.FormEvent) {
    e.preventDefault();
    if (!engagementId) return;
    setActErr(null);
    setBusy(true);
    try {
      await api.domains.assign(domain.id, engagementId, notes);
      setEngagementId("");
      setNotes("");
      reload();
      onChanged();
    } catch (err) {
      setActErr(err);
    } finally {
      setBusy(false);
    }
  }

  async function decide(aid: string, kind: "authorize" | "revoke") {
    setActErr(null);
    setBusyId(aid);
    try {
      if (kind === "authorize")
        await api.domains.authorizeAssignment(domain.id, aid);
      else await api.domains.revokeAssignment(domain.id, aid);
      reload();
      onChanged();
    } catch (err) {
      setActErr(err);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Section title="Engagement assignments">
      <ErrorBanner error={actErr} />
      <ErrorBanner error={error} />

      {loading ? (
        <Spinner />
      ) : !assignments || assignments.length === 0 ? (
        <Empty>No assignments yet.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Engagement</th>
              <th className="th">Status</th>
              <th className="th">Authorized</th>
              <th className="th"></th>
            </tr>
          }
        >
          {assignments.map((a) => (
            <tr key={a.id}>
              <td className="td text-slate-200">{engagementName(a.engagement_id)}</td>
              <td className="td">
                <Badge value={a.status} />
              </td>
              <td className="td text-slate-400">{fmtDate(a.authorized_at)}</td>
              <td className="td text-right">
                <div className="flex justify-end gap-2">
                  {a.status === "pending" && (
                    <button
                      className="btn-primary px-2 py-1 text-xs"
                      disabled={!isAdmin || busyId === a.id}
                      title={isAdmin ? "Authorize" : "Admin only"}
                      onClick={() => decide(a.id, "authorize")}
                    >
                      Authorize
                    </button>
                  )}
                  {a.status === "authorized" && (
                    <button
                      className="btn-danger px-2 py-1 text-xs"
                      disabled={!isAdmin || busyId === a.id}
                      title={isAdmin ? "Revoke" : "Admin only"}
                      onClick={() => decide(a.id, "revoke")}
                    >
                      Revoke
                    </button>
                  )}
                  {a.status === "revoked" && (
                    <span className="text-xs text-slate-500">revoked</span>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </Table>
      )}

      <form onSubmit={assign} className="mt-4 space-y-3">
        {!canAssign && (
          <p className="text-xs text-slate-500">
            A domain must be at least <code>verified</code> before it can be
            assigned (current: <code>{domain.status}</code>).
          </p>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Assign to engagement" hint="Authorized or active engagements only">
            <select
              className="input"
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              disabled={!canAssign}
            >
              <option value="">Select an engagement…</option>
              {assignable.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.name} · {e.client_name} ({e.effective_status})
                </option>
              ))}
            </select>
          </Field>
          <Field label="Notes (optional)">
            <input
              className="input"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              disabled={!canAssign}
            />
          </Field>
        </div>
        <button
          className="btn-ghost px-3 py-1.5 text-sm"
          disabled={busy || !canAssign || !engagementId}
        >
          {busy ? "Assigning…" : "Assign"}
        </button>
        {canAssign && assignable.length === 0 && engagements && (
          <p className="text-xs text-slate-500">
            No authorized or active engagements available to assign.
          </p>
        )}
      </form>
    </Section>
  );
}

function LifecyclePanel({
  domain,
  isAdmin,
  onChanged,
}: {
  domain: Domain;
  isAdmin: boolean;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState<"activate" | "suspend" | "retire" | null>(
    null
  );
  const [err, setErr] = useState<unknown>(null);

  const canActivate =
    domain.status === "verified" || domain.status === "suspended";
  const canSuspend = domain.status === "active";
  const canRetire = domain.status !== "retired";

  async function act(kind: "activate" | "suspend" | "retire") {
    if (kind === "retire") {
      if (
        !window.confirm(
          "Retire this domain? Retirement is terminal — the domain cannot be reactivated."
        )
      )
        return;
    }
    setErr(null);
    setBusy(kind);
    try {
      if (kind === "activate") await api.domains.activate(domain.id);
      else if (kind === "suspend") await api.domains.suspend(domain.id);
      else await api.domains.retire(domain.id);
      onChanged();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(null);
    }
  }

  return (
    <Section title="Lifecycle">
      <ErrorBanner error={err} />
      <div className="flex flex-wrap gap-2">
        <button
          className="btn-primary px-3 py-1.5 text-sm"
          disabled={!isAdmin || busy !== null || !canActivate}
          title={
            !isAdmin
              ? "Admin only"
              : canActivate
              ? "Activate (requires an authorized assignment)"
              : "Only a verified or suspended domain can be activated"
          }
          onClick={() => act("activate")}
        >
          {busy === "activate" ? "Activating…" : "Activate"}
        </button>
        <button
          className="btn-ghost px-3 py-1.5 text-sm"
          disabled={!isAdmin || busy !== null || !canSuspend}
          title={!isAdmin ? "Admin only" : "Suspend an active domain"}
          onClick={() => act("suspend")}
        >
          {busy === "suspend" ? "Suspending…" : "Suspend"}
        </button>
        <button
          className="btn-danger px-3 py-1.5 text-sm"
          disabled={!isAdmin || busy !== null || !canRetire}
          title={!isAdmin ? "Admin only" : "Retire (terminal)"}
          onClick={() => act("retire")}
        >
          {busy === "retire" ? "Retiring…" : "Retire"}
        </button>
      </div>
      {!isAdmin && (
        <p className="mt-2 text-xs text-slate-500">
          Lifecycle actions are admin-only.
        </p>
      )}
      <p className="mt-2 text-xs text-slate-500">
        Activation requires both a <code>verified</code> (or{" "}
        <code>suspended</code>) domain and at least one authorized assignment.
      </p>
    </Section>
  );
}

function DiagnosticsPanel({ id }: { id: string }) {
  const [diag, setDiag] = useState<DomainDiagnostics | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  async function run() {
    setErr(null);
    setBusy(true);
    try {
      setDiag(await api.domains.diagnostics(id));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section title="DNS / TLS diagnostics">
      <ErrorBanner error={err} />
      <button
        className="btn-ghost px-3 py-1.5 text-sm"
        disabled={busy}
        onClick={run}
      >
        {busy ? "Running…" : "Run diagnostics"}
      </button>

      {diag && (
        <div className="mt-4 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-md border border-ink-700 bg-ink-900/40 p-3">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
                DNS
              </h4>
              <dl className="space-y-1 text-sm">
                <DiagRow
                  label="Nameservers"
                  value={
                    diag.dns.nameservers && diag.dns.nameservers.length
                      ? diag.dns.nameservers.join(", ")
                      : "—"
                  }
                />
                <DiagRow label="SPF" value={diag.dns.spf || "—"} mono />
                <DiagRow label="DMARC" value={diag.dns.dmarc || "—"} mono />
                <DiagRow
                  label="DKIM"
                  value={diag.dns.dkim ?? diag.dns.dkim_note ?? "—"}
                />
              </dl>
            </div>

            <div className="rounded-md border border-ink-700 bg-ink-900/40 p-3">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
                TLS
              </h4>
              {diag.tls ? (
                <dl className="space-y-1 text-sm">
                  <DiagRow label="Subject CN" value={diag.tls.subject_cn || "—"} />
                  <DiagRow label="Issuer" value={diag.tls.issuer || "—"} />
                  <DiagRow
                    label="Not after"
                    value={fmtDate(diag.tls.not_after)}
                  />
                  <DiagRow
                    label="Days to expiry"
                    value={
                      diag.tls.days_until_expiry != null
                        ? String(diag.tls.days_until_expiry)
                        : "—"
                    }
                  />
                  <DiagRow
                    label="Covers domain"
                    value={diag.tls.covers_domain ? "yes" : "no"}
                  />
                </dl>
              ) : (
                <p className="text-sm text-slate-500">
                  No TLS certificate retrieved.
                </p>
              )}
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-md border border-amber-800/60 bg-amber-950/30 p-3">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-amber-300">
                Warnings
              </h4>
              {diag.warnings && diag.warnings.length ? (
                <ul className="list-disc space-y-1 pl-5 text-sm text-amber-200">
                  {diag.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-slate-500">None.</p>
              )}
            </div>

            <div className="rounded-md border border-rose-800/60 bg-rose-950/30 p-3">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-rose-300">
                Errors
              </h4>
              {diag.errors && diag.errors.length ? (
                <ul className="list-disc space-y-1 pl-5 text-sm text-rose-200">
                  {diag.errors.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-slate-500">None.</p>
              )}
            </div>
          </div>

          <p className="text-xs text-slate-500">
            Ownership verified: {diag.ownership.verified ? "yes" : "no"}.
            Diagnostics dial only the stored domain name and are read-only (not
            audited).
          </p>
        </div>
      )}
    </Section>
  );
}

function DiagRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex gap-2">
      <dt className="w-28 shrink-0 text-slate-500">{label}</dt>
      <dd
        className={`flex-1 break-all text-slate-200 ${mono ? "font-mono text-xs" : ""}`}
      >
        {value}
      </dd>
    </div>
  );
}
