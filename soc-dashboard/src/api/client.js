/**
 * API Client for XAI-IDPS-SOC Full Platform.
 */

const API_BASE = "/api/v1";

function getAuthHeaders() {
  const token = localStorage.getItem("xai_soc_token");
  const headers = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const config = {
    headers: getAuthHeaders(),
    ...options,
  };

  try {
    const res = await fetch(url, config);
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.detail || `HTTP Error ${res.status}`);
    }
    return await res.json();
  } catch (error) {
    console.error(`API Error on ${endpoint}:`, error);
    throw error;
  }
}

export const api = {
  // Auth
  login: async (username, password) => {
    const data = await request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    if (data.access_token) {
      localStorage.setItem("xai_soc_token", data.access_token);
      localStorage.setItem(
        "xai_soc_user",
        JSON.stringify({ username: data.username, role: data.role }),
      );
    }
    return data;
  },
  logout: () => {
    localStorage.removeItem("xai_soc_token");
    localStorage.removeItem("xai_soc_user");
  },
  getCurrentUser: () => {
    const userStr = localStorage.getItem("xai_soc_user");
    return userStr ? JSON.parse(userStr) : null;
  },
  getUsers: () => request("/auth/users"),
  createUser: (userData) =>
    request("/auth/users", {
      method: "POST",
      body: JSON.stringify(userData),
    }),
  deleteUser: (userId) =>
    request(`/auth/users/${userId}`, {
      method: "DELETE",
    }),
  updateUserRole: (userId, role) =>
    request(`/auth/users/${userId}/role`, {
      method: "PUT",
      body: JSON.stringify({ role }),
    }),

  // Alerts
  getAlerts: (params = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") {
        searchParams.append(k, v);
      }
    });
    return request(`/alerts?${searchParams.toString()}`);
  },
  getAlert: (id) => request(`/alerts/${id}`),
  getAlertExplanation: (id) => request(`/alerts/${id}/explanation`),
  updateAlertStatus: (id, status) =>
    request(`/alerts/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  deleteAlert: (id) =>
    request(`/alerts/${id}`, {
      method: "DELETE",
    }),
  submitFeedback: (id, { disposition, notes }) =>
    request(`/alerts/${id}/feedback`, {
      method: "POST",
      body: JSON.stringify({ disposition, notes }),
    }),

  // Cases
  getCases: (params = {}) => {
    const searchParams = new URLSearchParams(params);
    return request(`/cases?${searchParams.toString()}`);
  },
  getCase: (id) => request(`/cases/${id}`),
  createCase: (data) =>
    request("/cases", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateCase: (id, data) =>
    request(`/cases/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  // Automated IPS & Prevention
  getPreventionStatus: () => request("/prevention/status"),
  getBlockedIps: () => request("/prevention/blocks"),
  toggleDryRun: (enabled) =>
    request("/prevention/dry-run", {
      method: "POST",
      body: JSON.stringify({ enabled }),
    }),
  blockIp: (data) =>
    request("/prevention/block", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  unblockIp: (ip) =>
    request("/prevention/unblock", {
      method: "POST",
      body: JSON.stringify({ ip }),
    }),

  // AI Security Copilot
  askCopilot: (query, alert_id = null) =>
    request("/copilot/query", {
      method: "POST",
      body: JSON.stringify({ query, alert_id }),
    }),

  // Attack Simulator
  triggerSimulatedAttack: (attack_type, intensity = 1.0) =>
    request("/simulator/attack", {
      method: "POST",
      body: JSON.stringify({ attack_type, intensity }),
    }),

  // Digital Twin & Topology
  getTopologyGraph: () => request("/topology/graph"),

  // Analytics
  getSummary: () => request("/analytics/summary"),
  getTimeline: (hours = 48) => request(`/analytics/timeline?hours=${hours}`),
  getMetrics: () => request("/analytics/metrics"),

  // Reports & Viva
  getVivaReport: () => request("/reports/viva-summary"),

  // Settings
  getSettings: () => request("/settings"),
  updateWeights: (weights) =>
    request("/settings/weights", {
      method: "POST",
      body: JSON.stringify(weights),
    }),

  // Geolocation & Threat Intelligence
  getAlertsMap: (params = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") {
        searchParams.append(k, v);
      }
    });
    return request(`/geo/alerts-map?${searchParams.toString()}`);
  },
  getCountrySummary: () => request("/geo/country-summary"),
  getThreatIntelSummary: (minScore = 50) =>
    request(`/geo/threat-intel-summary?min_score=${minScore}`),

  // Deterministic Test Cases & IDPS Verification Suite
  getVerificationTests: () => request("/simulator/verification-tests"),
};
