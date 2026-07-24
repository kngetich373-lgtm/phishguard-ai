import axios from "axios";

const client = axios.create({
  baseURL: "/api",
});

client.interceptors.request.use((config) => {
  const token = localStorage.getItem("pg_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

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
