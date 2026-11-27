import React, { useEffect, useState } from "react";
import { CheckCircle2, Info, X } from "lucide-react";
import { alertsApi } from "../services/api";
import { RiskBadge, formatTimestamp } from "../components/RiskBadge";
import { useAuth } from "../context/AuthContext";

export function SecurityAlertsPage() {
  const { refreshOpenAlertsCount } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [filter, setFilter] = useState("");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadAlerts = async (statusFilter = filter) => {
    setLoading(true);
    setError("");
    try {
      const data = await alertsApi.list(statusFilter);
      setAlerts(data.alerts || []);
      await refreshOpenAlertsCount();
    } catch (err) {
      setError(err.message || "Failed to load security alerts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts("");
  }, []);

  const handleFilterChange = (nextFilter) => {
    setFilter(nextFilter);
    loadAlerts(nextFilter);
  };

  const handleResolve = async (alertId) => {
    try {
      const res = await alertsApi.resolve(alertId);
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? res.alert : a)));
      if (selectedAlert?.id === alertId) {
        setSelectedAlert(res.alert);
      }
      await refreshOpenAlertsCount();
    } catch (err) {
      setError(err.message || "Failed to resolve alert.");
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Alerts</h1>
          <p className="page-subtitle">
            Automatically triggered alerts for suspicious logins, high-risk vault access, and rule violations
          </p>
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          {[
            { label: "All", val: "" },
            { label: "Open", val: "OPEN" },
            { label: "Resolved", val: "RESOLVED" },
          ].map((opt) => (
            <button
              key={opt.label}
              type="button"
              className={`btn btn-sm ${filter === opt.val ? "btn-primary" : "btn-secondary"}`}
              onClick={() => handleFilterChange(opt.val)}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {error && <div className="alert-banner alert-error">{error}</div>}

      <div className="card">
        {loading ? (
          <p style={{ color: "var(--text-secondary)" }}>Loading security alerts...</p>
        ) : alerts.length === 0 ? (
          <div style={{ textAlign: "center", padding: "32px 16px", color: "var(--text-secondary)" }}>
            No security alerts match the selected filter.
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Event Type</th>
                  <th>Description</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>Timestamp</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td className="mono">#{alert.id}</td>
                    <td className="mono" style={{ fontSize: "0.82rem" }}>
                      {alert.event_type}
                    </td>
                    <td>{alert.alert_description}</td>
                    <td>
                      <RiskBadge level={alert.risk_level} score={alert.risk_score} />
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          alert.status === "OPEN" ? "badge-high" : "badge-low"
                        }`}
                      >
                        {alert.status}
                      </span>
                    </td>
                    <td style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}>
                      {formatTimestamp(alert.created_at)}
                    </td>
                    <td>
                      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => setSelectedAlert(alert)}
                        >
                          <Info size={13} /> Details
                        </button>
                        {alert.status === "OPEN" && (
                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            onClick={() => handleResolve(alert.id)}
                          >
                            <CheckCircle2 size={13} /> Resolve
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedAlert && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="modal-box">
            <div className="card-header">
              <h2 className="card-title">Security Alert #{selectedAlert.id} Details</h2>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedAlert(null)}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
              <RiskBadge level={selectedAlert.risk_level} score={selectedAlert.risk_score} />
              <span className={`badge ${selectedAlert.status === "OPEN" ? "badge-high" : "badge-low"}`}>
                {selectedAlert.status}
              </span>
              <span className="badge badge-cyan">{selectedAlert.event_type}</span>
            </div>

            <p style={{ marginBottom: 14, fontSize: "0.92rem" }}>
              {selectedAlert.alert_description}
            </p>

            <div style={{ marginBottom: 16 }}>
              <strong style={{ fontSize: "0.86rem", color: "var(--text-secondary)" }}>
                Rule-Based Score Breakdown:
              </strong>
              {selectedAlert.rule_breakdown && selectedAlert.rule_breakdown.length > 0 ? (
                <ul style={{ marginTop: 8, paddingLeft: 18, fontSize: "0.88rem" }}>
                  {selectedAlert.rule_breakdown.map((rule, idx) => (
                    <li key={idx} style={{ marginBottom: 6 }}>
                      <span className="mono" style={{ color: "var(--accent-cyan)" }}>
                        {rule.rule}
                      </span>{" "}
                      (+{rule.points} pts): {rule.reason}
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ color: "var(--text-muted)", fontSize: "0.86rem", marginTop: 6 }}>
                  No itemized rules recorded.
                </p>
              )}
            </div>

            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: 18 }}>
              Created: {formatTimestamp(selectedAlert.created_at)}
              {selectedAlert.resolved_at && ` • Resolved: ${formatTimestamp(selectedAlert.resolved_at)}`}
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
              {selectedAlert.status === "OPEN" && (
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => handleResolve(selectedAlert.id)}
                >
                  <CheckCircle2 size={15} /> Mark as Resolved
                </button>
              )}
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setSelectedAlert(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
