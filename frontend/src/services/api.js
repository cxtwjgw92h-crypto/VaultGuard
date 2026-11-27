/**
 * VaultGuard API Client
 *
 * Centralizes authenticated HTTP requests to the Flask REST API.
 * Automatically injects the stored JWT Bearer token and handles 401 session expiry.
 */

const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";

export function getStoredToken() {
  return sessionStorage.getItem("vaultguard_token") || localStorage.getItem("vaultguard_token");
}

export function setStoredToken(token) {
  if (token) {
    sessionStorage.setItem("vaultguard_token", token);
  } else {
    sessionStorage.removeItem("vaultguard_token");
    localStorage.removeItem("vaultguard_token");
  }
}

async function request(path, options = {}) {
  const token = getStoredToken();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(data.error || `Request failed (${response.status})`);
    err.status = response.status;
    err.data = data;
    throw err;
  }
  return data;
}

export const authApi = {
  register: (payload) => request("/auth/register", { method: "POST", body: JSON.stringify(payload) }),
  login: (payload) => request("/auth/login", { method: "POST", body: JSON.stringify(payload) }),
  logout: () => request("/auth/logout", { method: "POST" }),
  me: () => request("/auth/me"),
  changePassword: (payload) =>
    request("/auth/change-password", { method: "POST", body: JSON.stringify(payload) }),
};

export const vaultApi = {
  list: (search = "") =>
    request(`/credentials${search ? `?search=${encodeURIComponent(search)}` : ""}`),
  create: (payload) => request("/credentials", { method: "POST", body: JSON.stringify(payload) }),
  retrieve: (id) => request(`/credentials/${id}/retrieve`, { method: "POST" }),
  update: (id, payload) =>
    request(`/credentials/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
  remove: (id) => request(`/credentials/${id}`, { method: "DELETE" }),
};

export const monitoringApi = {
  dashboard: () => request("/monitoring/dashboard"),
  activity: (limit = 50) => request(`/monitoring/activity?limit=${limit}`),
};

export const riskApi = {
  events: (riskLevel = "") =>
    request(`/risk/events${riskLevel ? `?risk_level=${encodeURIComponent(riskLevel)}` : ""}`),
  config: () => request("/risk/config"),
};

export const alertsApi = {
  list: (status = "") =>
    request(`/alerts${status ? `?status=${encodeURIComponent(status)}` : ""}`),
  detail: (id) => request(`/alerts/${id}`),
  resolve: (id) => request(`/alerts/${id}/resolve`, { method: "PATCH" }),
  auditLogs: () => request("/alerts/audit-logs"),
};

export const assistantApi = {
  ask: (question) => request("/assistant/ask", { method: "POST", body: JSON.stringify({ question }) }),
  summary: () => request("/assistant/summary"),
};
