import React, { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { monitoringApi } from "../services/api";
import { formatTimestamp } from "../components/RiskBadge";

export function ActivityHistoryPage() {
  const [tab, setTab] = useState("timeline");
  const [data, setData] = useState({ timeline: [], login_events: [], audit_logs: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadActivity = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await monitoringApi.activity(100);
      setData(res);
    } catch (err) {
      setError(err.message || "Failed to load activity history.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadActivity();
  }, []);

  const rows =
    tab === "timeline"
      ? data.timeline
      : tab === "logins"
      ? data.login_events
      : data.audit_logs;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Activity History & Audit Logs</h1>
          <p className="page-subtitle">
            Complete accountability trail of logins, logouts, and vault access operations
          </p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={loadActivity}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {error && <div className="alert-banner alert-error">{error}</div>}

      <div style={{ display: "flex", gap: 8, marginBottom: 18, flexWrap: "wrap" }}>
        <button
          type="button"
          className={`btn btn-sm ${tab === "timeline" ? "btn-primary" : "btn-secondary"}`}
          onClick={() => setTab("timeline")}
        >
          Unified Timeline ({data.timeline.length})
        </button>
        <button
          type="button"
          className={`btn btn-sm ${tab === "logins" ? "btn-primary" : "btn-secondary"}`}
          onClick={() => setTab("logins")}
        >
          Login Events ({data.login_events.length})
        </button>
        <button
          type="button"
          className={`btn btn-sm ${tab === "audits" ? "btn-primary" : "btn-secondary"}`}
          onClick={() => setTab("audits")}
        >
          Audit Logs ({data.audit_logs.length})
        </button>
      </div>

      <div className="card">
        {loading ? (
          <p style={{ color: "var(--text-secondary)" }}>Loading activity logs...</p>
        ) : rows.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>No recorded activity in this category.</p>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Action / Event</th>
                  <th>Description</th>
                  <th>IP Address</th>
                  <th>Device / Browser</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((item) => {
                  const actionName = item.action || item.event_type;
                  const isFail = item.success_status === false;
                  return (
                    <tr key={item.id}>
                      <td>
                        <span className={`badge ${isFail ? "badge-high" : "badge-cyan"}`}>
                          {actionName}
                        </span>
                      </td>
                      <td>
                        {item.description ||
                          `${actionName.replace(/_/g, " ")} (${
                            item.success_status ? "Success" : "Failed"
                          })`}
                      </td>
                      <td className="mono">{item.ip_address}</td>
                      <td>{item.device_info}</td>
                      <td style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}>
                        {formatTimestamp(item.timestamp)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
