import type { ReactNode } from "react";
import { ApiError } from "../api/client";

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-5 flex items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex gap-2">{actions}</div>}
    </div>
  );
}

export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;
  let msg = String(error);
  let status: number | undefined;
  if (error instanceof ApiError) {
    status = error.status;
    msg = error.detail || error.title;
  } else if (error instanceof Error) {
    msg = error.message;
  }
  return (
    <div className="mb-4 rounded-md border border-rose-800 bg-rose-950/50 px-3 py-2 text-sm text-rose-200">
      {status ? <span className="font-semibold">{status} · </span> : null}
      {msg}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-ink-600 px-4 py-8 text-center text-sm text-slate-500">
      {children}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return <div className="py-8 text-center text-sm text-slate-500">{label}</div>;
}

const STATE_STYLES: Record<string, string> = {
  draft: "bg-slate-700 text-slate-200",
  scheduled: "bg-amber-900/60 text-amber-200",
  running: "bg-sky-900/60 text-sky-200",
  completed: "bg-emerald-900/60 text-emerald-200",
  paused: "bg-slate-700 text-slate-300",
  archived: "bg-slate-800 text-slate-400",
  pending: "bg-slate-700 text-slate-300",
  sent: "bg-sky-900/60 text-sky-200",
  delivered: "bg-sky-900/60 text-sky-200",
  opened: "bg-indigo-900/60 text-indigo-200",
  clicked: "bg-violet-900/60 text-violet-200",
  creds: "bg-rose-900/60 text-rose-200",
  session_hijacked: "bg-rose-900/60 text-rose-200",
  post_exploitation: "bg-rose-900/60 text-rose-200",
  bounced: "bg-orange-900/60 text-orange-200",
  failed: "bg-rose-950/70 text-rose-300",
  approved: "bg-emerald-900/60 text-emerald-200",
  rejected: "bg-rose-900/60 text-rose-200",
  // engagement statuses
  pending_authorization: "bg-amber-900/60 text-amber-200",
  authorized: "bg-emerald-900/60 text-emerald-200",
  active: "bg-emerald-900/60 text-emerald-200",
  expired: "bg-orange-900/60 text-orange-200",
  terminated: "bg-rose-950/70 text-rose-300",
};

export function Badge({ value }: { value: string }) {
  const cls = STATE_STYLES[value] ?? "bg-slate-700 text-slate-200";
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${cls}`}
    >
      {value}
    </span>
  );
}

export function Table({
  head,
  children,
}: {
  head: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-ink-700">
      <table className="min-w-full divide-y divide-ink-700">
        <thead className="bg-ink-800">{head}</thead>
        <tbody className="divide-y divide-ink-700 bg-ink-800/40">
          {children}
        </tbody>
      </table>
    </div>
  );
}

export function timeago(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return d.toLocaleString();
}
