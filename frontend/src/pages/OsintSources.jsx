import { useState, useEffect } from 'react';
import { Activity, CheckCircle, AlertCircle, Key, Clock, RefreshCw, ChevronDown, ChevronUp, Wifi } from 'lucide-react';
import { getSourceHealth } from '../services/api';

const CATEGORY_LABELS = {
  domain: 'Domain / Subdomain',
  dns: 'Passive DNS',
  certificate: 'Certificate Intelligence',
  ip: 'IP / ASN',
  technology: 'Technology Stack',
  email: 'Email Intelligence',
  username: 'Username / Identity',
  threat_intel: 'Threat Intelligence',
  github: 'GitHub Intelligence',
};

const CATEGORY_COLORS = {
  domain: 'var(--color-cyber-blue)',
  dns: '#22c55e',
  certificate: '#f59e0b',
  ip: '#8b5cf6',
  technology: '#06b6d4',
  email: '#ec4899',
  username: '#a78bfa',
  threat_intel: '#ef4444',
  github: '#e2e8f0',
};

function StatusBadge({ status }) {
  const configs = {
    ready: { color: '#22c55e', bg: 'rgba(34,197,94,0.1)', icon: <CheckCircle size={11} />, label: 'Ready' },
    key_missing: { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', icon: <Key size={11} />, label: 'Key Missing' },
    demo: { color: 'var(--color-cyber-blue)', bg: 'rgba(0,212,255,0.1)', icon: <Wifi size={11} />, label: 'Demo Mode' },
    error: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)', icon: <AlertCircle size={11} />, label: 'Error' },
  };
  const cfg = configs[status] || configs.error;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
      padding: '0.1875rem 0.625rem', borderRadius: 9999, fontSize: '0.6875rem', fontWeight: 700,
      background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}30`, letterSpacing: '0.04em',
    }}>
      {cfg.icon} {cfg.label}
    </span>
  );
}

function ProviderRow({ provider }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div style={{ border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden' }}>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0.875rem 1rem', background: 'var(--color-bg-card)',
          border: 'none', cursor: 'pointer', color: 'var(--color-text-primary)', textAlign: 'left',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
            <StatusBadge status={provider.status} />
            <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>{provider.display_name}</span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {provider.requires_key && (
            <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
              <Key size={10} style={{ display: 'inline', marginRight: '0.25rem' }} />key required
            </span>
          )}
          {provider.last_queried_at && (
            <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <Clock size={10} />
              {new Date(provider.last_queried_at).toLocaleTimeString()}
            </span>
          )}
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </div>
      </button>
      {expanded && (
        <div style={{ padding: '0.875rem 1rem', borderTop: '1px solid var(--color-border)', background: 'rgba(255,255,255,0.01)' }}>
          <p style={{ margin: '0 0 0.625rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
            {provider.description}
          </p>
          {provider.last_error && (
            <div style={{ display: 'flex', gap: '0.375rem', padding: '0.625rem 0.875rem', borderRadius: 8, background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)', fontSize: '0.75rem', color: '#ef4444' }}>
              <AlertCircle size={12} style={{ flexShrink: 0, marginTop: 1 }} />
              <span>Last error: {provider.last_error}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CategorySection({ category, providers }) {
  const color = CATEGORY_COLORS[category] || 'var(--color-text-muted)';
  const label = CATEGORY_LABELS[category] || category;
  const ready = providers.filter(p => p.status === 'ready' || p.status === 'demo').length;
  return (
    <div style={{ marginBottom: '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div style={{ width: 3, height: 16, borderRadius: 9999, background: color }} />
          <span style={{ fontWeight: 700, fontSize: '0.9375rem', color }}>{label}</span>
        </div>
        <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
          {ready}/{providers.length} active
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {providers.map(p => <ProviderRow key={`${p.name}-${p.category}`} provider={p} />)}
      </div>
    </div>
  );
}

export default function OsintSources() {
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(null);

  const fetchHealth = async () => {
    setLoading(true);
    try {
      const data = await getSourceHealth();
      setSources(data);
      setLastRefresh(new Date());
    } catch {
      setSources([]);
    }
    setLoading(false);
  };

  useEffect(() => { fetchHealth(); }, []);

  // Group by category
  const byCategory = {};
  sources.forEach(p => {
    const cat = p.category || 'general';
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(p);
  });

  const totalReady = sources.filter(p => p.status === 'ready' || p.status === 'demo').length;
  const totalMissing = sources.filter(p => p.status === 'key_missing').length;
  const totalError = sources.filter(p => p.status === 'error').length;

  return (
    <div style={{ padding: '2rem', maxWidth: 900, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '2rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(0,212,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Activity size={20} color="var(--color-cyber-blue)" />
            </div>
            <h1 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 800 }}>Source Health Dashboard</h1>
          </div>
          <p style={{ margin: 0, color: 'var(--color-text-muted)', fontSize: '0.875rem' }}>
            Real-time status of all OSINT providers. Configure API keys in <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>backend/.env</code>
          </p>
        </div>
        <button
          onClick={fetchHealth} disabled={loading}
          style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', padding: '0.5rem 1rem', borderRadius: 8, background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)', color: 'var(--color-cyber-blue)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}
        >
          <RefreshCw size={14} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
          Refresh
        </button>
      </div>

      {/* Summary stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
        {[
          { label: 'Total Providers', value: sources.length, color: 'var(--color-text-primary)' },
          { label: 'Active', value: totalReady, color: '#22c55e' },
          { label: 'Key Missing', value: totalMissing, color: '#f59e0b' },
          { label: 'Errors', value: totalError, color: '#ef4444' },
        ].map(s => (
          <div key={s.label} style={{ padding: '1rem', background: 'var(--color-bg-card)', borderRadius: 10, border: '1px solid var(--color-border)', textAlign: 'center' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: s.color }}>{s.value}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.25rem' }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Refresh timestamp */}
      {lastRefresh && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', marginBottom: '1.5rem', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
          <Clock size={12} />
          Last refreshed: {lastRefresh.toLocaleTimeString()}
        </div>
      )}

      {/* Per-category sections */}
      {Object.entries(byCategory).map(([cat, providers]) => (
        <CategorySection key={cat} category={cat} providers={providers} />
      ))}

      {/* Setup guide */}
      <div style={{ marginTop: '2rem', padding: '1.25rem', borderRadius: 12, background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.15)' }}>
        <h3 style={{ margin: '0 0 0.75rem', fontSize: '0.9375rem', fontWeight: 700, color: '#8b5cf6' }}>
          Configuring API Keys
        </h3>
        <p style={{ margin: '0 0 0.5rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
          Add your API keys to <code style={{ fontFamily: 'var(--font-mono)' }}>backend/.env</code>. See <code style={{ fontFamily: 'var(--font-mono)' }}>.env.example</code> for a complete template.
          The system works in Demo Mode without any keys using the ApexNova Technologies dataset.
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem', marginTop: '0.75rem' }}>
          {['GITHUB_TOKEN (free)', 'VIRUSTOTAL_API_KEY (free)', 'SHODAN_API_KEY (free tier)', 'HUNTER_API_KEY (25 req/month free)', 'EMAILREP_API_KEY (100 req/day free)'].map(k => (
            <code key={k} style={{ fontSize: '0.6875rem', padding: '0.125rem 0.5rem', borderRadius: 6, background: 'rgba(255,255,255,0.06)', color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>{k}</code>
          ))}
        </div>
      </div>
    </div>
  );
}
