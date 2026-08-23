import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

// Scans
export const createScan = (data) => api.post('/scans', data).then(r => r.data);
export const listScans = () => api.get('/scans').then(r => r.data);
export const getScan = (id) => api.get(`/scans/${id}`).then(r => r.data);
export const getDashboardStats = (id) => api.get(`/scans/${id}/dashboard`).then(r => r.data);

// Findings
export const getFindings = (scanId, params = {}) =>
  api.get(`/scans/${scanId}/findings`, { params }).then(r => r.data);
export const getFinding = (id) => api.get(`/findings/${id}`).then(r => r.data);

// Graph
export const getGraphData = (scanId) => api.get(`/scans/${scanId}/graph`).then(r => r.data);
export const getRelationships = (scanId) => api.get(`/scans/${scanId}/relationships`).then(r => r.data);

// Attack Paths
export const getAttackPaths = (scanId) => api.get(`/scans/${scanId}/attack-paths`).then(r => r.data);

// Risk
export const getRiskScores = (scanId) => api.get(`/scans/${scanId}/risk`).then(r => r.data);
export const getRiskSummary = (scanId) => api.get(`/scans/${scanId}/risk/summary`).then(r => r.data);

// Recommendations
export const getRecommendations = (scanId) => api.get(`/scans/${scanId}/recommendations`).then(r => r.data);

// Timeline
export const getTimeline = (scanId) => api.get(`/scans/${scanId}/timeline`).then(r => r.data);

// Reports
export const generateReport = (scanId) => api.post(`/scans/${scanId}/report`).then(r => r.data);

// Sources
export const getSources = () => api.get('/sources').then(r => r.data);

// Settings
export const getSettings = () => api.get('/settings').then(r => r.data);

export default api;
