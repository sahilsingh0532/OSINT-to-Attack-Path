import { useState, useEffect } from 'react';
import { Activity, CheckCircle, AlertCircle, Key, Clock, RefreshCw, ChevronDown, ChevronUp, Wifi, Play, Zap, ShieldAlert, Timer } from 'lucide-react';
import { getSourceHealth, testAllSources, testSource } from '../services/api';

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
    ready: { color: '#22c55e', bg: 'rgba(34,197,94,0.1)', icon: <CheckCircle size={11} />, label: 'Active & Ready' },
    key_missing: { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', icon: <Key size={11} />, label: 'Key Missing' },
    auth_failed: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)', icon: <ShieldAlert size={11} />, label: 'Auth Failed (401/403)' },
    rate_limited: { color: '#f97316', bg: 'rgba(249,115,22,0.1)', icon: <Timer size={11} />, label: 'Rate Limited (429)' },
    timeout: { color: '#eab308', bg: 'rgba(234,179,8,0.1)', icon: <Clock size={11} />, label: 'Timed Out' },
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

function ProviderRow({ provider, onTest, isTesting }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div style={{ border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden', background: 'var(--color-bg-card)' }}>
      <div
        style={{
          width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0.875rem 1rem',
          color: 'var(--color-text-primary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1 }}>
          <StatusBadge status={provider.status} />
          <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>{provider.display_name}</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {provider.last_latency_ms !== null && provider.last_latency_ms !== undefined && (
            <span style={{ fontSize: '0.6875rem', color: '#22c55e', background: 'rgba(34,197,94,0.08)', padding: '0.125rem 0.375rem', borderRadius: 4, fontFamily: 'var(--font-mono)' }}>
              {provider.last_latency_ms} ms
            </span>
          )}

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

          {/* Test Provider Button */}
          <button
            onClick={() => onTest(provider.name, provider.category)}
            disabled={isTesting}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.25rem',
              padding: '0.25rem 0.625rem', borderRadius: 6,
              background: 'rgba(0, 212, 255, 0.08)', border: '1px solid rgba(0, 212, 255, 0.25)',
              color: 'var(--color-cyber-blue)', fontSize: '0.6875rem', fontWeight: 600,
              cursor: isTesting ? 'not-allowed' : 'pointer',
            }}
          >
            {isTesting ? <RefreshCw size={10} style={{ animation: 'spin 1s linear infinite' }} /> : <Zap size={10} />}
            Test
          </button>

          <button
            onClick={() => setExpanded(!expanded)}
            style={{ background: 'transparent', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
          >
            {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        </div>
      </div>

      {expanded && (
        <div style={{ padding: '0.875rem 1rem', borderTop: '1px solid var(--color-border)', background: 'rgba(255,255,255,0.01)' }}>
          <p style={{ margin: '0 0 0.625rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
            {provider.description}
          </p>

          <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '0.625rem', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
            <div>Total Queries: <strong style={{ color: 'var(--color-text-primary)' }}>{provider.total_queries || 0}</strong></div>
            <div>Total Errors: <strong style={{ color: provider.total_errors > 0 ? '#ef4444' : 'var(--color-text-primary)' }}>{provider.total_errors || 0}</strong></div>
            <div>Last Findings: <strong style={{ color: 'var(--color-cyber-green)' }}>{provider.last_findings_count || 0}</strong></div>
          </div>

          {provider.last_error && (
            <div style={{ display: 'flex', gap: '0.375rem', padding: '0.625rem 0.875rem', borderRadius: 8, background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)', fontSize: '0.75rem', color: '#ef4444' }}>
              <AlertCircle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
              <div>
                <strong>Provider Error / Diagnostics:</strong>
                <div style={{ marginTop: '0.125rem', fontFamily: 'var(--font-mono)' }}>{provider.last_error}</div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CategorySection({ category, providers, onTest, testingProvider }) {
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
        {providers.map(p => (
          <ProviderRow
            key={`${p.name}-${p.category}`}
            provider={p}
            onTest={onTest}
            isTesting={testingProvider === `${p.name}:${p.category}`}
          />
        ))}
      </div>
    </div>
  );
}

export default function OsintSources() {
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(false);
  const [testingAll, setTestingAll] = useState(false);
  const [testingProvider, setTestingProvider] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [testSummary, setTestSummary] = useState(null);

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

  const handleTestAll = async () => {
    setTestingAll(true);
    setTestSummary(null);
    try {
      const results = await testAllSources('example.com');
      const passed = results.filter(r => r.ok).length;
      setTestSummary({ total: results.length, passed, failed: results.length - passed });
      await fetchHealth();
    } catch (err) {
      console.error(err);
    }
    setTestingAll(false);
  };

  const handleTestSingle = async (name, category) => {
    const key = `${name}:${category}`;
    setTestingProvider(key);
    try {
      await testSource(name, category, 'example.com');
      await fetchHealth();
    } catch (err) {
      console.error(err);
    }
    setTestingProvider(null);
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
  const totalError = sources.filter(p => p.status === 'error' || p.status === 'auth_failed' || p.status === 'rate_limited' || p.status === 'timeout').length;

  return (
    <div style={{ padding: '2rem', maxWidth: 900, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '2rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(0,212,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Activity size={20} color="var(--color-cyber-blue)" />
            </div>
            <h1 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 800 }}>Source Health & API Diagnostics</h1>
          </div>
          <p style={{ margin: 0, color: 'var(--color-text-muted)', fontSize: '0.875rem' }}>
            Real-time status and live connection tests for all OSINT providers. Keys configured in <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>backend/.env</code>
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            onClick={handleTestAll} disabled={testingAll || loading}
            style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', padding: '0.5rem 1rem', borderRadius: 8, background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(34,197,94,0.2))', border: '1px solid var(--color-cyber-blue)', color: 'var(--color-cyber-blue)', cursor: testingAll ? 'not-allowed' : 'pointer', fontSize: '0.875rem', fontWeight: 700 }}
          >
            {testingAll ? <RefreshCw size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Zap size={14} />}
            {testingAll ? 'Testing All APIs...' : 'Test All APIs'}
          </button>
          <button
            onClick={fetchHealth} disabled={loading || testingAll}
            style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', padding: '0.5rem 1rem', borderRadius: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--color-border)', color: 'var(--color-text-primary)', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}
          >
            <RefreshCw size={14} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            Refresh
          </button>
        </div>
      </div>

      {/* Test feedback notification */}
      {testSummary && (
        <div style={{
          marginBottom: '1.5rem', padding: '0.875rem 1.25rem', borderRadius: 10,
          background: testSummary.passed > 0 ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
          border: `1px solid ${testSummary.passed > 0 ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}`,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Zap size={16} color={testSummary.passed > 0 ? '#22c55e' : '#ef4444'} />
            <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>
              Diagnostic Complete: {testSummary.passed} providers verified operational, {testSummary.failed} missing keys or degraded.
            </span>
          </div>
          <button onClick={() => setTestSummary(null)} style={{ background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', fontSize: '0.75rem' }}>Dismiss</button>
        </div>
      )}

      {/* Summary stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
        {[
          { label: 'Total Providers', value: sources.length, color: 'var(--color-text-primary)' },
          { label: 'Active & Ready', value: totalReady, color: '#22c55e' },
          { label: 'Key Missing', value: totalMissing, color: '#f59e0b' },
          { label: 'Errors / Degraded', value: totalError, color: '#ef4444' },
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
        <CategorySection
          key={cat}
          category={cat}
          providers={providers}
          onTest={handleTestSingle}
          testingProvider={testingProvider}
        />
      ))}

      {/* Setup guide */}
      <div style={{ marginTop: '2rem', padding: '1.25rem', borderRadius: 12, background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.15)' }}>
        <h3 style={{ margin: '0 0 0.75rem', fontSize: '0.9375rem', fontWeight: 700, color: '#8b5cf6' }}>
          Configuring API Keys
        </h3>
        <p style={{ margin: '0 0 0.5rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
          Add your API keys to <code style={{ fontFamily: 'var(--font-mono)' }}>backend/.env</code>. See <code style={{ fontFamily: 'var(--font-mono)' }}>.env.example</code> for a complete template.
          The free providers (HackerTarget, RDAP, DNS Query, Shodan InternetDB, HTTP Header Fingerprinting, GitHub Intel) work automatically without any paid subscriptions.
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
