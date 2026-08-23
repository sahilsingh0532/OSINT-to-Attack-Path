export const getRiskColor = (level) => {
  const colors = {
    'CRITICAL': '#dc2626',
    'VERY HIGH': '#ea580c',
    'HIGH': '#f59e0b',
    'MEDIUM': '#3b82f6',
    'LOW': '#22c55e',
  };
  return colors[level] || '#64748b';
};

export const getRiskBg = (level) => {
  const bgs = {
    'CRITICAL': 'risk-critical',
    'VERY HIGH': 'risk-very-high',
    'HIGH': 'risk-high',
    'MEDIUM': 'risk-medium',
    'LOW': 'risk-low',
  };
  return bgs[level] || 'risk-low';
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
