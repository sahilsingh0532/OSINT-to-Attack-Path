import axios from 'axios';

const rawBaseURL = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || '/api';
const cleanBaseURL = rawBaseURL.replace(/\/+$/, '');
const baseURL = cleanBaseURL.startsWith('http') && !cleanBaseURL.endsWith('/api')
  ? `${cleanBaseURL}/api`
  : cleanBaseURL;

export const API_URL = rawBaseURL;

const api = axios.create({
  baseURL,
  headers: { 'Content-Type': 'application/json' },
});

// ── Scans ──────────────────────────────────────────────────────────────────
export const createScan = (data) => api.post('/scans', data).then(r => r.data);
export const listScans = () => api.get('/scans').then(r => r.data);
export const getScan = (id) => api.get(`/scans/${id}`).then(r => r.data);
export const getDashboardStats = (id) => api.get(`/scans/${id}/dashboard`).then(r => r.data);

// ── Findings ───────────────────────────────────────────────────────────────
export const getFindings = (scanId, params = {}) =>
  api.get(`/scans/${scanId}/findings`, { params }).then(r => r.data);
export const getFinding = (id) => api.get(`/findings/${id}`).then(r => r.data);
export const getConfidenceBreakdown = (findingId) =>
  api.get(`/findings/${findingId}/confidence`).then(r => r.data);

// ── Typed intelligence endpoints ───────────────────────────────────────────
export const getDomains = (scanId) => api.get(`/scans/${scanId}/domains`).then(r => r.data);
export const getSubdomains = (scanId) => api.get(`/scans/${scanId}/subdomains`).then(r => r.data);
export const getCertificates = (scanId) => api.get(`/scans/${scanId}/certificates`).then(r => r.data);
export const getIPs = (scanId) => api.get(`/scans/${scanId}/ips`).then(r => r.data);
export const getEmails = (scanId) => api.get(`/scans/${scanId}/emails`).then(r => r.data);
export const getUsernames = (scanId) => api.get(`/scans/${scanId}/usernames`).then(r => r.data);
export const getTechnologies = (scanId) => api.get(`/scans/${scanId}/technologies`).then(r => r.data);

// ── Source comparison ──────────────────────────────────────────────────────
export const getSourceComparison = (scanId, findingType = 'subdomain') =>
  api.get(`/scans/${scanId}/source-comparison`, { params: { finding_type: findingType } }).then(r => r.data);

// ── Graph ──────────────────────────────────────────────────────────────────
export const getGraphData = (scanId) => api.get(`/scans/${scanId}/graph`).then(r => r.data);
export const getRelationships = (scanId) => api.get(`/scans/${scanId}/relationships`).then(r => r.data);

// ── Attack Paths ───────────────────────────────────────────────────────────
export const getAttackPaths = (scanId) => api.get(`/scans/${scanId}/attack-paths`).then(r => r.data);

// ── Risk ───────────────────────────────────────────────────────────────────
export const getRiskScores = (scanId) => api.get(`/scans/${scanId}/risk`).then(r => r.data);
export const getRiskSummary = (scanId) => api.get(`/scans/${scanId}/risk/summary`).then(r => r.data);

// ── Recommendations ────────────────────────────────────────────────────────
export const getRecommendations = (scanId) =>
  api.get(`/scans/${scanId}/recommendations`).then(r => r.data);

// ── Timeline ───────────────────────────────────────────────────────────────
export const getTimeline = (scanId) => api.get(`/scans/${scanId}/timeline`).then(r => r.data);

// ── Reports ────────────────────────────────────────────────────────────────
export const generateReport = (scanId) =>
  api.post(`/scans/${scanId}/report`).then(r => r.data);

// ── Sources ────────────────────────────────────────────────────────────────
export const getSources = () => api.get('/sources').then(r => r.data);
export const getSourceHealth = () => api.get('/sources/health').then(r => r.data);

// ── Settings ───────────────────────────────────────────────────────────────
export const getSettings = () => api.get('/settings').then(r => r.data);

export default api;
