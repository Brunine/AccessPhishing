import { useState } from "react";
import { api } from "../api/client";
import { useSession } from "../auth";
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

export default function Approvals() {
  const { isAdmin } = useSession();
  const { data, loading, error, reload } = useAsync(() => api.approvals.list());
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionErr, setActionErr] = useState<unknown>(null);

  async function decide(id: string, kind: "approve" | "reject") {
    setActionErr(null);
    setBusyId(id);
    try {
      if (kind === "approve") await api.approvals.approve(id);
      else await api.approvals.reject(id);
      reload();
    } catch (e) {
      setActionErr(e);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <PageHeader
        title="Approvals"
        subtitle={
          isAdmin
            ? "Review and decide pending approvals."
            : "Pending approvals. Only admins can approve or reject."
        }
      />
      <ErrorBanner error={actionErr} />
      <ErrorBanner error={error} />

      {loading ? (
        <Spinner />
      ) : !data || data.length === 0 ? (
        <Empty>No approvals requested.</Empty>
      ) : (
        <Table
          head={
            <tr>
              <th className="th">Subject</th>
              <th className="th">Status</th>
              <th className="th">Requested</th>
              <th className="th">Decided</th>
              <th className="th"></th>
            </tr>
          }
        >
          {data.map((a) => {
            const pending = a.status === "draft";
            return (
              <tr key={a.id}>
                <td className="td">
                  <div className="text-slate-300">{a.subject_type}</div>
                  <div className="font-mono text-xs text-slate-500">{a.subject_id}</div>
                </td>
                <td className="td">
                  <Badge value={a.status} />
                </td>
                <td className="td text-slate-400">{timeago(a.created_at)}</td>
                <td className="td text-slate-400">
                  {a.decided_at ? timeago(a.decided_at) : "—"}
                </td>
                <td className="td text-right">
                  {pending ? (
                    <div className="flex justify-end gap-2">
                      <button
                        className="btn-primary px-2 py-1 text-xs"
                        disabled={!isAdmin || busyId === a.id}
                        title={isAdmin ? "Approve" : "Admin only"}
                        onClick={() => decide(a.id, "approve")}
                      >
                        Approve
                      </button>
                      <button
                        className="btn-danger px-2 py-1 text-xs"
                        disabled={!isAdmin || busyId === a.id}
                        title={isAdmin ? "Reject" : "Admin only"}
                        onClick={() => decide(a.id, "reject")}
                      >
                        Reject
                      </button>
                    </div>
                  ) : (
                    <span className="text-xs text-slate-500">decided</span>
                  )}
                </td>
              </tr>
            );
          })}
        </Table>
      )}
      {!isAdmin && (
        <p className="mt-3 text-xs text-slate-500">
          You are signed in as a non-admin; decision buttons are disabled.
        </p>
      )}
    </div>
  );
}
