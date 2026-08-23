import { useEffect } from 'react';
import { Radar, CheckCircle, AlertCircle, Info, ExternalLink } from 'lucide-react';
import useScanStore from '../stores/scanStore';

export default function Reconnaissance() {
  const { sources, loadSources, currentScan, findings } = useScanStore();

  useEffect(() => {
    loadSources();
  }, []);

  // Group findings by source
  const findingsBySource = {};
  findings.forEach(f => {
    if (!findingsBySource[f.source]) findingsBySource[f.source] = [];
    findingsBySource[f.source].push(f);
  });

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Passive Reconnaissance</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          Intelligence sources and their findings.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
        {sources.map(source => {
          const sourceFindings = findingsBySource[source.name] || [];
          const avgConfidence = sourceFindings.length > 0
            ? (sourceFindings.reduce((sum, f) => sum + f.confidence, 0) / sourceFindings.length)
            : 0;

          return (
            <div key={source.name} className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {/* Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
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
                    {source.status === 'completed' ? (
                      <CheckCircle size={12} color="var(--color-cyber-green)" />
                    ) : source.status === 'not_configured' ? (
                      <AlertCircle size={12} color="var(--color-text-muted)" />
                    ) : (
                      <Info size={12} color="var(--color-cyber-blue)" />
                    )}
                    <span style={{ fontSize: '0.75rem', color: source.status === 'completed' ? 'var(--color-cyber-green)' : 'var(--color-text-muted)', fontWeight: 500 }}>
                      {source.status === 'completed' ? 'Completed' : source.status === 'not_configured' ? 'Not Configured' : 'Ready'}
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

              {/* Demo Badge */}
              {source.is_demo && (
                <div style={{
                  padding: '0.375rem 0.75rem',
                  background: 'rgba(245, 158, 11, 0.08)',
                  border: '1px solid rgba(245, 158, 11, 0.2)',
                  borderRadius: 6,
                  fontSize: '0.6875rem',
                  color: '#f59e0b',
                  fontWeight: 500,
                  textAlign: 'center',
                }}>
                  Demo Dataset / API Not Configured
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
