import { useState } from "react";
import { api, ApiError } from "../api/client";
import type { OSINTAvailability, OSINTResult } from "../api/types";
import { useAsync } from "../hooks";
import {
  Empty,
  ErrorBanner,
  Field,
  PageHeader,
  Spinner,
  timeago,
} from "../components/ui";

export default function Recon() {
  const status = useAsync(() => api.osint.status());
  const results = useAsync(() => api.osint.results());

  return (
    <div>
      <PageHeader
        title="Recon"
        subtitle="Passive public-info aggregation via the OSINT service (subdomains, lookalike domains, RDAP availability). No active scanning."
        actions={<StatusPill status={status} />}
      />

      <CollectForm onDone={() => results.reload()} disabled={!serviceUsable(status)} />

      <div className="mt-6">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Stored collections</h2>
          <button className="text-xs text-slate-400 hover:text-slate-200" onClick={() => results.reload()}>
            Refresh
          </button>
        </div>
        <ErrorBanner error={results.error} />
        {results.loading ? (
          <Spinner />
        ) : !results.data || results.data.length === 0 ? (
          <Empty>No collections yet. Run one above.</Empty>
        ) : (
          <div className="space-y-3">
            {results.data.map((r) => (
              <ResultCard key={r.id} result={r} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

type StatusState = ReturnType<typeof useAsync<{ service: "ok" | "down" }>>;

// serviceUsable: true unless the service is explicitly not configured (503).
function serviceUsable(status: StatusState): boolean {
  if (status.error instanceof ApiError && status.error.status === 503) return false;
  return true;
}

function StatusPill({ status }: { status: StatusState }) {
  if (status.loading) {
    return <span className="rounded bg-ink-700 px-2 py-0.5 text-xs text-slate-400">checking…</span>;
  }
  if (status.error) {
    const notConfigured = status.error instanceof ApiError && status.error.status === 503;
    return (
      <span
        className={`rounded px-2 py-0.5 text-xs ${
          notConfigured ? "bg-slate-700 text-slate-300" : "bg-rose-900/60 text-rose-200"
        }`}
        title={notConfigured ? "Set OSINT_BASE_URL on the API to enable" : String(status.error)}
      >
        {notConfigured ? "not configured" : "error"}
      </span>
    );
  }
  const ok = status.data?.service === "ok";
  return (
    <span
      className={`rounded px-2 py-0.5 text-xs ${
        ok ? "bg-emerald-900/60 text-emerald-200" : "bg-amber-900/60 text-amber-200"
      }`}
    >
      service {status.data?.service}
    </span>
  );
}

function CollectForm({ onDone, disabled }: { onDone: () => void; disabled: boolean }) {
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [banner, setBanner] = useState("");
  const [fieldErr, setFieldErr] = useState("");

  async function collect(e: React.FormEvent) {
    e.preventDefault();
    setBanner("");
    setFieldErr("");
    setBusy(true);
    try {
      await api.osint.collect(domain.trim());
      setDomain("");
      onDone();
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) {
        setFieldErr(err.detail || "Invalid domain");
      } else if (err instanceof ApiError && err.status === 503) {
        setBanner("OSINT service unreachable or not configured (503).");
      } else {
        setBanner(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={collect} className="card space-y-3">
      <h2 className="text-sm font-semibold text-slate-200">Collect</h2>
      {banner && (
        <div className="rounded-md border border-rose-800 bg-rose-950/50 px-3 py-2 text-sm text-rose-200">
          {banner}
        </div>
      )}
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-[16rem] flex-1">
          <Field label="Domain" hint="A single registrable domain, e.g. example.com">
            <input
              className="input"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              disabled={disabled}
            />
          </Field>
          {fieldErr && <p className="mt-1 text-xs text-rose-300">{fieldErr}</p>}
        </div>
        <button className="btn-primary h-[34px]" disabled={busy || disabled || domain.trim() === ""}>
          {busy ? "Collecting…" : "Collect"}
        </button>
      </div>
      {disabled && (
        <p className="text-xs text-slate-500">
          OSINT service not configured — set <code>OSINT_BASE_URL</code> on the API.
        </p>
      )}
      {busy && (
        <p className="text-xs text-slate-500">
          This can take up to the service timeout (OSINT_TIMEOUT) while subdomains,
          lookalikes, and availability are gathered.
        </p>
      )}
    </form>
  );
}

function availabilityBadge(a: OSINTAvailability) {
  if (a.available === true) {
    return <span className="rounded bg-emerald-900/60 px-2 py-0.5 text-xs text-emerald-200">available</span>;
  }
  if (a.available === false) {
    return <span className="rounded bg-slate-700 px-2 py-0.5 text-xs text-slate-300">registered</span>;
  }
  return <span className="rounded bg-ink-700 px-2 py-0.5 text-xs text-slate-400">unknown</span>;
}

function ResultCard({ result }: { result: OSINTResult }) {
  const c = result.result;
  const subs = c.subdomains ?? [];
  const looks = c.lookalikes ?? [];
  const avail = c.availability ?? [];

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <span className="font-medium text-slate-100">{result.domain}</span>
        <span className="text-xs text-slate-500">collected {timeago(result.created_at)}</span>
      </div>

      <div className="mt-3 space-y-2">
        <details className="rounded border border-ink-700 bg-ink-800/50 px-3 py-2">
          <summary className="cursor-pointer text-sm text-slate-300">
            Subdomains ({subs.length})
            {c.subdomain_source ? <span className="ml-2 text-xs text-slate-500">via {c.subdomain_source}</span> : null}
          </summary>
          {subs.length === 0 ? (
            <p className="mt-2 text-xs text-slate-500">None found.</p>
          ) : (
            <ul className="mt-2 grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2 md:grid-cols-3">
              {subs.map((s) => (
                <li key={s} className="font-mono text-xs text-slate-300">{s}</li>
              ))}
            </ul>
          )}
        </details>

        <details className="rounded border border-ink-700 bg-ink-800/50 px-3 py-2">
          <summary className="cursor-pointer text-sm text-slate-300">
            Lookalike candidates ({looks.length})
          </summary>
          {looks.length === 0 ? (
            <p className="mt-2 text-xs text-slate-500">None generated.</p>
          ) : (
            <ul className="mt-2 grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2 md:grid-cols-3">
              {looks.map((l) => (
                <li key={l.domain} className="flex items-center justify-between gap-2 font-mono text-xs text-slate-300">
                  <span>{l.domain}</span>
                  <span className="rounded bg-ink-700 px-1.5 text-[10px] text-slate-400">{l.fuzzer}</span>
                </li>
              ))}
            </ul>
          )}
        </details>

        <details className="rounded border border-ink-700 bg-ink-800/50 px-3 py-2">
          <summary className="cursor-pointer text-sm text-slate-300">
            Availability ({avail.length})
          </summary>
          {avail.length === 0 ? (
            <p className="mt-2 text-xs text-slate-500">Not checked.</p>
          ) : (
            <ul className="mt-2 space-y-1">
              {avail.map((a) => (
                <li key={a.domain} className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-slate-300">{a.domain}</span>
                  {availabilityBadge(a)}
                </li>
              ))}
            </ul>
          )}
        </details>
      </div>
    </div>
  );
}
