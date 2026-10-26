export const getRiskColor = (level) => {
  const normalized = String(level || '').toUpperCase().trim();
  const colors = {
    'CRITICAL': '#dc2626',
    'CRITICAL RISK': '#dc2626',
    'CRITICAL THREAT': '#dc2626',
    'VERY HIGH': '#ea580c',
    'HIGH': '#f59e0b',
    'HIGH RISK': '#f59e0b',
    'MEDIUM': '#3b82f6',
    'MODERATE': '#3b82f6',
    'MODERATE RISK': '#3b82f6',
    'LOW': '#22c55e',
    'LOW RISK': '#22c55e',
    'VERY LOW': '#10b981',
    'VERY LOW RISK': '#10b981',
    'MINIMAL RISK': '#10b981',
    'CLEAN': '#10b981',
    'CLEAN / SECURE': '#10b981',
  };
  return colors[normalized] || '#64748b';
};

export const getRiskBg = (level) => {
  const normalized = String(level || '').toUpperCase().trim();
  const bgs = {
    'CRITICAL': 'risk-critical',
    'CRITICAL RISK': 'risk-critical',
    'CRITICAL THREAT': 'risk-critical',
    'VERY HIGH': 'risk-very-high',
    'HIGH': 'risk-high',
    'HIGH RISK': 'risk-high',
    'MEDIUM': 'risk-medium',
    'MODERATE': 'risk-medium',
    'MODERATE RISK': 'risk-medium',
    'LOW': 'risk-low',
    'LOW RISK': 'risk-low',
    'VERY LOW': 'risk-low',
    'VERY LOW RISK': 'risk-low',
    'MINIMAL RISK': 'risk-low',
    'CLEAN': 'risk-low',
  };
  return bgs[normalized] || 'risk-low';
};

export const getNodeColor = (type) => {
  const colors = {
    organization: '#a855f7',
    domain: '#00d4ff',
    subdomain: '#38bdf8',
    ip: '#14b8a6',
    asn: '#0d9488',
    certificate: '#f59e0b',
    technology: '#8b5cf6',
    repository: '#22c55e',
    identity: '#ec4899',
    exposure: '#ef4444',
    threat_indicator: '#dc2626',
    darkweb_reference: '#991b1b',
  };
  return colors[type] || '#64748b';
};

export const getNodeShape = (type) => {
  const shapes = {
    organization: 'diamond',
    domain: 'ellipse',
    subdomain: 'ellipse',
    ip: 'round-rectangle',
    asn: 'round-rectangle',
    certificate: 'star',
    technology: 'hexagon',
    repository: 'round-triangle',
    identity: 'ellipse',
    exposure: 'vee',
    threat_indicator: 'triangle',
    darkweb_reference: 'triangle',
  };
  return shapes[type] || 'ellipse';
};

export const formatDate = (dateStr) => {
  if (!dateStr) return 'N/A';
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
};

export const formatDateTime = (dateStr) => {
  if (!dateStr) return 'N/A';
  return new Date(dateStr).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
};

export const formatConfidence = (val) => `${Math.round(val * 100)}%`;

export const capitalize = (str) => {
  if (!str) return '';
  return str.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
};
