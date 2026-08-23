import useScanStore from '../stores/scanStore';
import { ShieldAlert, Globe, AlertTriangle } from 'lucide-react';
import { formatDate, formatConfidence } from '../utils/helpers';

export default function ThreatIntelligence() {
  const { findings } = useScanStore();
  const threats = findings.filter(f => f.finding_type === 'threat_indicator');
  const darkweb = findings.filter(f => f.finding_type === 'darkweb_reference');

  const Section = ({ title, icon: Icon, items, color }) => (
    <div style={{ marginBottom: '2rem' }}>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1.125rem', fontWeight: 600, marginBottom: '1rem' }}>
        <Icon size={20} color={color} />
        {title}
      </h2>
      {items.length === 0 ? (
        <p style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem' }}>No data available. Run a scan first.</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {items.map(f => (
            <div key={f.id} className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 600 }}>{f.title}</h3>
                  <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                    {f.description}
                  </p>
                </div>
                <span style={{
                  fontSize: '0.6875rem', padding: '0.125rem 0.5rem', borderRadius: 9999,
                  background: f.observation_type === 'observed' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(245, 158, 11, 0.1)',
                  color: f.observation_type === 'observed' ? '#22c55e' : '#f59e0b',
                  fontWeight: 500, flexShrink: 0,
                }}>
                  {f.observation_type}
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem' }}>
                <div style={{ padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8, fontSize: '0.75rem' }}>
                  <div style={{ fontSize: '0.5625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.125rem' }}>Source</div>
                  {f.source}
                </div>
                <div style={{ padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8, fontSize: '0.75rem' }}>
                  <div style={{ fontSize: '0.5625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.125rem' }}>Confidence</div>
                  {formatConfidence(f.confidence)}
                </div>
                <div style={{ padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8, fontSize: '0.75rem' }}>
                  <div style={{ fontSize: '0.5625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.125rem' }}>Evidence</div>
                  <span style={{ fontSize: '0.6875rem' }}>{f.evidence}</span>
                </div>
                <div style={{ padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8, fontSize: '0.75rem' }}>
                  <div style={{ fontSize: '0.5625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.125rem' }}>Discovered</div>
                  {formatDate(f.discovered_at)}
                </div>
              </div>

              {f.finding_type === 'darkweb_reference' && (
                <div style={{
                  marginTop: '0.75rem', padding: '0.5rem 0.75rem',
                  background: 'rgba(245, 158, 11, 0.06)', border: '1px solid rgba(245, 158, 11, 0.15)',
                  borderRadius: 6, fontSize: '0.6875rem', color: '#f59e0b',
                }}>
                  Ahmia Demo Dataset — This data is simulated for academic demonstration.
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Threat Intelligence</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          Public threat intelligence indicators and dark web references.
        </p>
      </div>

      <Section title="Threat Intelligence Indicators" icon={ShieldAlert} items={threats} color="#dc2626" />
      <Section title="Onion / Dark-Web Intelligence" icon={Globe} items={darkweb} color="#991b1b" />

      <div style={{
        padding: '0.75rem 1rem', background: 'rgba(220, 38, 38, 0.06)', border: '1px solid rgba(220, 38, 38, 0.15)',
        borderRadius: 8, fontSize: '0.6875rem', color: 'var(--color-text-muted)',
      }}>
        This module only processes safe, publicly indexed threat-intelligence references. No dark web crawling, illegal content download, or sensitive personal data collection is performed.
      </div>
    </div>
  );
}
