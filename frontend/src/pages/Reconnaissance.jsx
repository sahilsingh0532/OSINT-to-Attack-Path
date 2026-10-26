import { useState, useEffect } from 'react';
import { Radar, CheckCircle, AlertCircle, Info, ExternalLink, Globe, Key, ShieldCheck, Zap, Activity, Filter } from 'lucide-react';
import useScanStore from '../stores/scanStore';

const CATEGORY_NAMES = {
  domain: 'Domain & Subdomain',
  dns: 'Passive DNS',
  certificate: 'Certificate Logs',
  ip: 'IP & Infrastructure',
  technology: 'Tech Fingerprinting',
  email: 'Email Intelligence',
  username: 'Username Intelligence',
  threat_intel: 'Threat Feeds',
  github: 'GitHub Intelligence',
};

export default function Reconnaissance() {
  const { sources, loadSources, currentScan, findings } = useScanStore();
  const [selectedCategory, setSelectedCategory] = useState('all');

  useEffect(() => {
    loadSources();
  }, []);

  // Group findings by source
  const findingsBySource = {};
  findings.forEach(f => {
    if (!findingsBySource[f.source]) findingsBySource[f.source] = [];
    findingsBySource[f.source].push(f);
  });

  const categories = ['all', ...Array.from(new Set(sources.map(s => s.category).filter(Boolean)))];

  const filteredSources = selectedCategory === 'all'
    ? sources
    : sources.filter(s => s.category === selectedCategory);

  const openProtocolCount = sources.filter(s => !s.requires_key).length;
  const configuredApiCount = sources.filter(s => s.requires_key && s.status !== 'key_missing').length;

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Passive Reconnaissance</h1>
          <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
            Real-time intelligence sources operating over open protocols and configured APIs.
          </p>
        </div>

        {/* Live Status Pill */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          background: 'var(--color-bg-card)',
          border: '1px solid var(--color-border)',
          borderRadius: 8,
          padding: '0.5rem 1rem',
          fontSize: '0.75rem',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <span style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: 'var(--color-cyber-green)',
              boxShadow: '0 0 8px var(--color-cyber-green)',
            }} />
            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>Live Mode</span>
          </div>
          <span style={{ color: 'var(--color-border)' }}>|</span>
          <span style={{ color: 'var(--color-cyber-blue)', fontWeight: 500 }}>
            {openProtocolCount} Open Protocols
          </span>
          <span style={{ color: 'var(--color-border)' }}>|</span>
          <span style={{ color: 'var(--color-cyber-green)', fontWeight: 500 }}>
            {configuredApiCount} Configured APIs
          </span>
          {currentScan?.target_domain && (
            <>
              <span style={{ color: 'var(--color-border)' }}>|</span>
              <span style={{ color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>
                Target: {currentScan.target_domain}
              </span>
            </>
          )}
        </div>
      </div>

      {/* Category Filter Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            style={{
              padding: '0.375rem 0.75rem',
              borderRadius: 6,
              fontSize: '0.75rem',
              fontWeight: selectedCategory === cat ? 600 : 500,
              background: selectedCategory === cat ? 'rgba(0, 212, 255, 0.12)' : 'var(--color-bg-secondary)',
              color: selectedCategory === cat ? 'var(--color-cyber-blue)' : 'var(--color-text-muted)',
              border: selectedCategory === cat ? '1px solid var(--color-cyber-blue)' : '1px solid var(--color-border)',
              cursor: 'pointer',
              textTransform: 'capitalize',
            }}
          >
            {cat === 'all' ? 'All Sources' : (CATEGORY_NAMES[cat] || cat)}
          </button>
        ))}
      </div>

      {/* Sources Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
        {filteredSources.map(source => {
          const sourceFindings = findingsBySource[source.name] || [];
          const avgConfidence = sourceFindings.length > 0
            ? (sourceFindings.reduce((sum, f) => sum + f.confidence, 0) / sourceFindings.length)
            : 0;

          const isOpenProtocol = !source.requires_key;
          const isKeyConfigured = source.requires_key && source.status !== 'key_missing';
          const isKeyMissing = source.requires_key && source.status === 'key_missing';

          return (
            <div key={`${source.name}-${source.category || 'general'}`} className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {/* Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <Radar size={16} color="var(--color-cyber-blue)" />
                    <span style={{ fontSize: '0.9375rem', fontWeight: 600 }}>{source.display_name}</span>
                  </div>
                  <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text-muted)', lineHeight: 1.4 }}>
                    {source.description}
                  </p>
                </div>
              </div>

              {/* Status Row */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem' }}>
                <div style={{ textAlign: 'center', padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                  <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.25rem' }}>Status</div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem' }}>
                    {sourceFindings.length > 0 ? (
                      <CheckCircle size={12} color="var(--color-cyber-green)" />
                    ) : isKeyMissing ? (
                      <Key size={12} color="#f59e0b" />
                    ) : (
                      <CheckCircle size={12} color="var(--color-cyber-blue)" />
                    )}
                    <span style={{
                      fontSize: '0.75rem',
                      color: sourceFindings.length > 0 ? 'var(--color-cyber-green)' : isKeyMissing ? '#f59e0b' : 'var(--color-cyber-blue)',
                      fontWeight: 600,
                    }}>
                      {sourceFindings.length > 0 ? 'Active' : isKeyMissing ? 'Key Missing' : 'Ready'}
                    </span>
                  </div>
                </div>

                <div style={{ textAlign: 'center', padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                  <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.25rem' }}>Findings</div>
                  <div style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-cyber-blue)' }}>
                    {sourceFindings.length}
                  </div>
                </div>

                <div style={{ textAlign: 'center', padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                  <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.25rem' }}>Confidence</div>
                  <div style={{ fontSize: '0.875rem', fontWeight: 600, color: avgConfidence >= 0.8 ? 'var(--color-cyber-green)' : avgConfidence >= 0.5 ? 'var(--color-cyber-orange)' : 'var(--color-text-muted)' }}>
                    {sourceFindings.length > 0 ? `${Math.round(avgConfidence * 100)}%` : 'N/A'}
                  </div>
                </div>
              </div>

              {/* Protocol / API Integration Badge */}
              {isOpenProtocol ? (
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.375rem',
                  padding: '0.375rem 0.75rem',
                  background: 'rgba(0, 212, 255, 0.08)',
                  border: '1px solid rgba(0, 212, 255, 0.25)',
                  borderRadius: 6,
                  fontSize: '0.6875rem',
                  color: 'var(--color-cyber-blue)',
                  fontWeight: 600,
                }}>
                  <Globe size={12} />
                  <span>Open Protocol / Public API (Live)</span>
                </div>
              ) : isKeyConfigured ? (
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.375rem',
                  padding: '0.375rem 0.75rem',
                  background: 'rgba(34, 197, 94, 0.08)',
                  border: '1px solid rgba(34, 197, 94, 0.25)',
                  borderRadius: 6,
                  fontSize: '0.6875rem',
                  color: 'var(--color-cyber-green)',
                  fontWeight: 600,
                }}>
                  <ShieldCheck size={12} />
                  <span>Live API Connected</span>
                </div>
              ) : (
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.375rem',
                  padding: '0.375rem 0.75rem',
                  background: 'rgba(245, 158, 11, 0.08)',
                  border: '1px solid rgba(245, 158, 11, 0.2)',
                  borderRadius: 6,
                  fontSize: '0.6875rem',
                  color: '#f59e0b',
                  fontWeight: 500,
                }}>
                  <Key size={12} />
                  <span>API Key Optional (Configurable in .env)</span>
                </div>
              )}

              {/* Findings Preview */}
              {sourceFindings.length > 0 && (
                <div style={{ maxHeight: 150, overflowY: 'auto' }}>
                  {sourceFindings.slice(0, 5).map(f => (
                    <div key={f.id} style={{
                      padding: '0.375rem 0',
                      borderBottom: '1px solid var(--color-border)',
                      fontSize: '0.75rem',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)' }}>
                        {f.value.length > 40 ? f.value.slice(0, 40) + '...' : f.value}
                      </span>
                      <span style={{
                        fontSize: '0.625rem', padding: '0.0625rem 0.375rem', borderRadius: 9999,
                        background: 'rgba(0, 212, 255, 0.1)', color: 'var(--color-cyber-blue)',
                      }}>
                        {f.finding_type}
                      </span>
                    </div>
                  ))}
                  {sourceFindings.length > 5 && (
                    <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', padding: '0.375rem 0', textAlign: 'center' }}>
                      +{sourceFindings.length - 5} more findings
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
