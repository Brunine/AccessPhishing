import type { ReportTotals, TimelineBucket } from "../api/types";

// Shared palette (hex) matching the state badges, for SVG fills.
const STATE_COLOR: Record<string, string> = {
  pending: "#64748b",
  sent: "#38bdf8",
  delivered: "#0ea5e9",
  opened: "#818cf8",
  clicked: "#a78bfa",
  creds: "#fb7185",
  session_hijacked: "#f43f5e",
  post_exploitation: "#e11d48",
  bounced: "#fb923c",
  failed: "#fda4af",
  reported: "#2dd4bf",
};

function pct(n: number, d: number): number {
  return d > 0 ? Math.round((n / d) * 1000) / 10 : 0;
}

const FUNNEL_STAGES: { key: keyof ReportTotals; label: string }[] = [
  { key: "sent", label: "Sent" },
  { key: "delivered", label: "Delivered" },
  { key: "opened", label: "Opened" },
  { key: "clicked", label: "Clicked" },
  { key: "creds", label: "Submitted creds" },
  { key: "session_hijacked", label: "Session hijacked" },
];

// FunnelChart renders the recipient funnel as proportional horizontal bars.
export function FunnelChart({ totals }: { totals: ReportTotals }) {
  const base = totals.recipients || 1;
  return (
    <div className="space-y-2">
      {FUNNEL_STAGES.map((s) => {
        const n = totals[s.key];
        const width = Math.max(1.5, (n / base) * 100);
        return (
          <div key={s.key} className="flex items-center gap-3">
            <div className="w-32 shrink-0 text-xs text-slate-400">{s.label}</div>
            <div className="h-6 flex-1 overflow-hidden rounded bg-ink-700">
              <div
                className="flex h-6 items-center rounded"
                style={{ width: `${width}%`, backgroundColor: STATE_COLOR[s.key] }}
              >
                <span className="pl-2 text-xs font-medium text-ink-900">
                  {n}
                </span>
              </div>
            </div>
            <div className="w-14 shrink-0 text-right text-xs tabular-nums text-slate-400">
              {pct(n, base)}%
            </div>
          </div>
        );
      })}
      {(totals.bounced > 0 || totals.failed > 0 || totals.pending > 0) && (
        <div className="pt-1 text-xs text-slate-500">
          {totals.pending} pending · {totals.bounced} bounced · {totals.failed} failed
          {" "}(of {totals.recipients} recipients)
        </div>
      )}
    </div>
  );
}

// TimelineChart renders event counts per time bucket as stacked bars (SVG).
export function TimelineChart({ timeline }: { timeline: TimelineBucket[] }) {
  if (timeline.length === 0) {
    return <div className="text-sm text-slate-500">No events yet.</div>;
  }
  // Event types present, in a stable funnel-ish order.
  const order = ["sent", "delivered", "opened", "clicked", "creds", "session_hijacked", "post_exploitation", "bounced", "failed", "reported"];
  const present = order.filter((t) => timeline.some((b) => (b.counts[t] ?? 0) > 0));

  const totals = timeline.map((b) => present.reduce((s, t) => s + (b.counts[t] ?? 0), 0));
  const maxTotal = Math.max(1, ...totals);

  const W = 600;
  const H = 180;
  const padL = 28;
  const padB = 28;
  const padT = 8;
  const plotW = W - padL;
  const plotH = H - padB - padT;
  const n = timeline.length;
  const slot = plotW / n;
  const barW = Math.min(36, slot * 0.7);

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Event timeline">
        {/* y gridlines */}
        {[0, 0.5, 1].map((f) => {
          const y = padT + plotH * (1 - f);
          return (
            <g key={f}>
              <line x1={padL} y1={y} x2={W} y2={y} stroke="#1b2233" strokeWidth={1} />
              <text x={0} y={y + 3} fontSize={9} fill="#64748b">
                {Math.round(maxTotal * f)}
              </text>
            </g>
          );
        })}
        {timeline.map((b, i) => {
          const x = padL + slot * i + (slot - barW) / 2;
          let yCursor = padT + plotH;
          return (
            <g key={b.bucket}>
              {present.map((t) => {
                const v = b.counts[t] ?? 0;
                if (v === 0) return null;
                const h = (v / maxTotal) * plotH;
                yCursor -= h;
                return (
                  <rect
                    key={t}
                    x={x}
                    y={yCursor}
                    width={barW}
                    height={h}
                    fill={STATE_COLOR[t] ?? "#64748b"}
                  >
                    <title>{`${t}: ${v}`}</title>
                  </rect>
                );
              })}
              <text
                x={x + barW / 2}
                y={H - padB + 12}
                fontSize={8}
                fill="#64748b"
                textAnchor="middle"
              >
                {shortBucket(b.bucket)}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
        {present.map((t) => (
          <span key={t} className="flex items-center gap-1 text-xs text-slate-400">
            <span
              className="inline-block h-2.5 w-2.5 rounded-sm"
              style={{ backgroundColor: STATE_COLOR[t] }}
            />
            {t}
          </span>
        ))}
      </div>
    </div>
  );
}

function shortBucket(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  // "MM-DD HH:00" style, compact.
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  const da = String(d.getDate()).padStart(2, "0");
  const hr = d.getHours();
  return hr === 0 ? `${mo}/${da}` : `${mo}/${da} ${String(hr).padStart(2, "0")}h`;
}

// RateBar renders a single 0..1 rate as a labeled horizontal bar.
export function RateBar({ label, value, color }: { label: string; value: number; color?: string }) {
  const p = Math.round(value * 1000) / 10;
  return (
    <div className="flex items-center gap-3">
      <div className="w-28 shrink-0 text-xs text-slate-400">{label}</div>
      <div className="h-2 flex-1 overflow-hidden rounded bg-ink-700">
        <div className="h-2 rounded" style={{ width: `${Math.min(100, p)}%`, backgroundColor: color ?? "#818cf8" }} />
      </div>
      <div className="w-12 shrink-0 text-right text-xs tabular-nums text-slate-400">{p}%</div>
    </div>
  );
}
