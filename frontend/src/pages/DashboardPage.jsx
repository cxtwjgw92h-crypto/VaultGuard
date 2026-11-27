import React, { useEffect, useState } from "react";
import {
  KeyRound,
  LogIn,
  ShieldAlert,
  BellRing,
  Activity,
  RefreshCw,
  AlertCircle,
  Loader2,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import { monitoringApi } from "../services/api";
import { RiskBadge, formatTimestamp } from "../components/RiskBadge";
import { useAuth } from "../context/AuthContext";

const RISK_COLORS = {
  LOW: "#10b981",
  MEDIUM: "#f59e0b",
  HIGH: "#ef4444",
};

export function DashboardPage() {
  const { refreshOpenAlertsCount } = useAuth();
  const [data, setData] = useState(null);
  // `loading` tracks any in-progress fetch (initial load OR a Refresh click)
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadDashboard = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await monitoringApi.dashboard();
      setData(res);
      await refreshOpenAlertsCount();
    } catch (err) {
      setError(err.message || "Failed to load dashboard data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Show full-page loader only on the very first load (no data yet)
  if (loading && !data) {
    return (
      <div className="card" style={{ display: "flex", alignItems: "center", gap: 12, padding: 28 }}>
        <Loader2 size={20} style={{ animation: "spin 1s linear infinite", color: "var(--accent-cyan)" }} />
        <span>Loading real-time security telemetry...</span>
      </div>
    );
  }

  const metrics = data?.metrics || {};
  const riskOverTime = data?.risk_over_time || [];
  const riskDistribution = data?.risk_distribution || [];
  const recentLogins = data?.recent_logins || [];
  const recentCreds = data?.recent_credential_access || [];
  const recentEvents = data?.recent_security_events || [];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-subtitle">
            Live vault telemetry, authentication monitoring, and rule-based risk analytics
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: "0.84rem", color: "var(--text-secondary)" }}>
              Current Status:
            </span>
            <RiskBadge level={metrics.security_status} />
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={loadDashboard}
            disabled={loading}
            aria-label="Refresh dashboard data"
            style={{ minWidth: 100 }}
          >
            {loading ? (
              <>
                <Loader2
                  size={14}
                  style={{ animation: "spin 1s linear infinite" }}
                />
                Refreshing...
              </>
            ) : (
              <>
                <RefreshCw size={14} />
                Refresh
              </>
            )}
          </button>
        </div>
      </div>

      {/* Inline error banner — shown inside the page, not as a full-page replacement */}
      {error && (
        <div className="alert-banner alert-error" style={{ marginBottom: 16 }}>
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      {/* Subtle refresh overlay so user can see stale data while new data loads */}
      <div style={{ opacity: loading ? 0.6 : 1, transition: "opacity 0.2s ease", pointerEvents: loading ? "none" : "auto" }}>
      <div className="stats-grid">
        <div className="stat-card">
          <div>
            <div className="stat-label">Saved Credentials</div>
            <div className="stat-value">{metrics.total_credentials ?? 0}</div>
          </div>
          <div className="stat-icon">
            <KeyRound size={20} />
          </div>
        </div>

        <div className="stat-card">
          <div>
            <div className="stat-label">Successful Logins</div>
            <div className="stat-value" style={{ color: "var(--risk-low)" }}>
              {metrics.total_successful_logins ?? 0}
            </div>
          </div>
          <div className="stat-icon" style={{ background: "var(--risk-low-bg)", color: "var(--risk-low)" }}>
            <LogIn size={20} />
          </div>
        </div>

        <div className="stat-card">
          <div>
            <div className="stat-label">Failed Logins</div>
            <div className="stat-value" style={{ color: "var(--risk-medium)" }}>
              {metrics.total_failed_logins ?? 0}
            </div>
          </div>
          <div className="stat-icon" style={{ background: "var(--risk-medium-bg)", color: "var(--risk-medium)" }}>
            <ShieldAlert size={20} />
          </div>
        </div>

        <div className="stat-card">
          <div>
            <div className="stat-label">Open Security Alerts</div>
            <div className="stat-value" style={{ color: metrics.open_alerts > 0 ? "var(--risk-high)" : "var(--text-primary)" }}>
              {metrics.open_alerts ?? 0}
              <span style={{ fontSize: "0.82rem", color: "var(--text-muted)", fontWeight: 500, marginLeft: 6 }}>
                / {metrics.total_alerts ?? 0} total
              </span>
            </div>
          </div>
          <div className="stat-icon" style={{ background: "var(--risk-high-bg)", color: "var(--risk-high)" }}>
            <BellRing size={20} />
          </div>
        </div>
      </div>

      {/* Interactive Charts */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Risk Scores Over Time</h2>
            <span className="badge badge-cyan">Last {riskOverTime.length} events</span>
          </div>
          {riskOverTime.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
              No evaluated security events recorded yet.
            </p>
          ) : (
            <div style={{ width: "100%", height: 260 }}>
              <ResponsiveContainer>
                <AreaChart data={riskOverTime}>
                  <defs>
                    <linearGradient id="riskScoreFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#22d3ee" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="label" stroke="#64748b" fontSize={12} />
                  <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      border: "1px solid #213052",
                      borderRadius: 8,
                      color: "#e2e8f0",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="risk_score"
                    name="Risk Score"
                    stroke="#22d3ee"
                    strokeWidth={2.5}
                    fill="url(#riskScoreFill)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Risk Level Distribution</h2>
            <span className="badge badge-neutral">LOW / MEDIUM / HIGH</span>
          </div>
          <div style={{ width: "100%", height: 260 }}>
            <ResponsiveContainer>
              <BarChart data={riskDistribution}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="level" stroke="#94a3b8" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    border: "1px solid #213052",
                    borderRadius: 8,
                    color: "#e2e8f0",
                  }}
                />
                <Bar dataKey="count" name="Events" radius={[6, 6, 0, 0]}>
                  {riskDistribution.map((entry) => (
                    <Cell key={entry.level} fill={RISK_COLORS[entry.level] || "#3b82f6"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Logins & Credential Access */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Recent Login Activity</h2>
          </div>
          {recentLogins.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>No login activity recorded.</p>
          ) : (
            <div className="table-wrapper">
              <table className="table">
                <thead>
                  <tr>
                    <th>Event</th>
                    <th>IP Address</th>
                    <th>Device</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {recentLogins.map((ev) => (
                    <tr key={ev.id}>
                      <td>
                        <span className={`badge ${ev.success_status ? "badge-low" : "badge-high"}`}>
                          {ev.event_type}
                        </span>
                      </td>
                      <td className="mono">{ev.ip_address}</td>
                      <td>{ev.device_info}</td>
                      <td style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}>
                        {formatTimestamp(ev.timestamp)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Recent Credential Access Activity</h2>
          </div>
          {recentCreds.length === 0 ? (
            <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
              No credential vault operations recorded yet.
            </p>
          ) : (
            <div className="table-wrapper">
              <table className="table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Details</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {recentCreds.map((log) => (
                    <tr key={log.id}>
                      <td>
                        <span className="badge badge-cyan">{log.action}</span>
                      </td>
                      <td>{log.description}</td>
                      <td style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}>
                        {formatTimestamp(log.timestamp)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Recent Security Events */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            <Activity size={18} color="#22d3ee" />
            Recent Evaluated Security Events
          </h2>
        </div>
        {recentEvents.length === 0 ? (
          <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>No security events yet.</p>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Event Type</th>
                  <th>Description</th>
                  <th>Risk Classification</th>
                  <th>Triggered Rules</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {recentEvents.map((ev) => (
                  <tr key={ev.id}>
                    <td className="mono" style={{ fontSize: "0.82rem" }}>
                      {ev.event_type}
                    </td>
                    <td>{ev.description}</td>
                    <td>
                      <RiskBadge level={ev.risk_level} score={ev.risk_score} />
                    </td>
                    <td style={{ fontSize: "0.82rem", color: "var(--text-secondary)" }}>
                      {ev.rule_breakdown && ev.rule_breakdown.length > 0
                        ? ev.rule_breakdown.map((r) => `${r.rule} (+${r.points})`).join(", ")
                        : "Baseline activity (0 pts)"}
                    </td>
                    <td style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}>
                      {formatTimestamp(ev.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      </div>{/* end opacity wrapper */}
    </div>
  );
}
