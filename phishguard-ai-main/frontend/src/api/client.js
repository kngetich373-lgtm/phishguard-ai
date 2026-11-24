import axios from "axios";

const client = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "/api",
});
let refreshRequest = null;

client.interceptors.request.use((config) => {
  const token = localStorage.getItem("pg_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

client.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    const path = original?.url || "";
    if (
      error.response?.status !== 401 ||
      !original ||
      original._retry ||
      path.includes("/auth/login") ||
      path.includes("/auth/register") ||
      path.includes("/auth/refresh") ||
      path.includes("/auth/logout")
    ) {
      return Promise.reject(error);
    }

    const refreshToken = localStorage.getItem("pg_refresh_token");
    if (!refreshToken) return Promise.reject(error);
    original._retry = true;
    try {
      if (!refreshRequest) {
        refreshRequest = axios
          .post(`${client.defaults.baseURL}/auth/refresh`, { refresh_token: refreshToken })
          .then((response) => response.data)
          .finally(() => {
            refreshRequest = null;
          });
      }
      const tokens = await refreshRequest;
      localStorage.setItem("pg_token", tokens.access_token);
      localStorage.setItem("pg_refresh_token", tokens.refresh_token);
      original.headers.Authorization = `Bearer ${tokens.access_token}`;
      return client(original);
    } catch (refreshError) {
      localStorage.removeItem("pg_token");
      localStorage.removeItem("pg_refresh_token");
      return Promise.reject(refreshError);
    }
  },
);

export default client;

// ---- Auth ----
export const registerUser = (payload) => client.post("/auth/register", payload);

export const loginUser = (email, password) => {
  const form = new URLSearchParams();
  form.append("username", email);
  form.append("password", password);
  return client.post("/auth/login", form, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
};

export const fetchMe = () => client.get("/auth/me");
export const logoutUser = (refreshToken) => {
  if (!refreshToken) return Promise.resolve();
  return axios.post(`${client.defaults.baseURL}/auth/logout`, {
    refresh_token: refreshToken,
  });
};

// ---- Scanning ----
export const scanUrl = (url) => client.post("/scan/url", { url });
export const scanSms = (message, sender) => client.post("/scan/sms", { message, sender });
export const scanEmail = (subject, body, sender) => client.post("/scan/email", { subject, body, sender });
export const gmailStatus = () => client.get("/scan/email/gmail/status");

// ---- Alerts ----
export const fetchAlerts = () => client.get("/alerts");
export const markAlertRead = (id) => client.post(`/alerts/${id}/read`);

// ---- Reports ----
export const fetchSummary = () => client.get("/reports/summary");
export const fetchHistory = () => client.get("/reports/history");
export const fetchApiKeys = () => client.get("/reports/api-keys");
export const createApiKey = (label) => client.post("/reports/api-keys", null, { params: { label } });

// ---- Team ----
export const fetchMyTeam = () => client.get("/team/me");
export const inviteMember = (payload) => client.post("/team/invite", payload);
