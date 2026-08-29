import { useState } from 'react';
import { Mail, Search, CheckCircle, AlertTriangle, Shield, Users, Clock, ExternalLink } from 'lucide-react';
import useScanStore from '../stores/scanStore';
import { getEmails } from '../services/api';
import EvidenceModal from '../components/common/EvidenceModal';

function SourcePill({ source }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
      padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.625rem', fontWeight: 600,
      background: 'rgba(0,212,255,0.08)', color: 'var(--color-cyber-blue)',
      border: '1px solid rgba(0,212,255,0.15)', fontFamily: 'var(--font-mono)',
      textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>{source}</span>
  );
}

function ConfidenceBar({ value }) {
  const pct = Math.round(value * 100);
  const color = pct >= 85 ? '#22c55e' : pct >= 65 ? '#f59e0b' : '#ef4444';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
      <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 9999 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 9999 }} />
      </div>
      <span style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', color, fontWeight: 700 }}>{pct}%</span>
    </div>
  );
}

function EmailCard({ finding, onViewMore }) {
  const sources = finding.sources || [finding.source];
  const sc = finding.source_count || sources.length;

  return (
    <div style={{
      background: 'var(--color-bg-card)', border: '1px solid var(--color-border)',
      borderRadius: 12, padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(0,212,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Mail size={18} color="var(--color-cyber-blue)" />
          </div>
          <div>
            <div style={{ fontSize: '0.9375rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>
              {finding.value}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
              {finding.description?.slice(0, 80)}
            </div>
          </div>
        </div>
        {sc > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.625rem', borderRadius: 9999, background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.2)' }}>
            <CheckCircle size={10} color="#22c55e" />
            <span style={{ fontSize: '0.6875rem', color: '#22c55e', fontWeight: 700 }}>{sc} sources</span>
          </div>
        )}
      </div>

      <ConfidenceBar value={finding.confidence || 0} />

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
        {sources.map(s => <SourcePill key={s} source={s} />)}
      </div>

      {finding.evidence && (
        <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', lineHeight: 1.5, padding: '0.5rem 0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: 6, border: '1px solid var(--color-border)' }}>
          {finding.evidence}
        </div>
      )}

      <button
        onClick={() => onViewMore(finding)}
        style={{ alignSelf: 'flex-start', padding: '0.375rem 0.875rem', borderRadius: 8, background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)', color: 'var(--color-cyber-blue)', fontSize: '0.8125rem', cursor: 'pointer', fontWeight: 600 }}
      >
        View More
      </button>
    </div>
  );
}

export default function EmailIntelligence() {
  const { currentScan } = useScanStore();
  const activeScanId = currentScan?.id || null;
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [filter, setFilter] = useState('');

  const handleLoad = async () => {
    if (!activeScanId) return;
    setLoading(true);
    try {
      const data = await getEmails(activeScanId);
      setEmails(data);
      setLoaded(true);
    } catch (e) {
      setEmails([]);
    }
    setLoading(false);
  };

  const filtered = emails.filter(e =>
    !filter || e.value?.toLowerCase().includes(filter.toLowerCase()) || e.description?.toLowerCase().includes(filter.toLowerCase())
  );

  const multiSource = emails.filter(e => (e.source_count || 1) > 1);

  return (
    <div style={{ padding: '2rem', maxWidth: 900, margin: '0 auto' }}>
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(0,212,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Mail size={20} color="var(--color-cyber-blue)" />
          </div>
          <h1 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 800 }}>Email Intelligence</h1>
        </div>
        <p style={{ margin: 0, color: 'var(--color-text-muted)', fontSize: '0.875rem' }}>
          Email addresses discovered via passive sources: Hunter.io, GitHub commits, EmailRep.io.
          No credentials, no breach data, no unauthorized access.
        </p>
      </div>

      {/* Stats bar */}
      {loaded && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
          {[
            { label: 'Emails Found', value: emails.length, color: 'var(--color-cyber-blue)' },
            { label: 'Multi-Source', value: multiSource.length, color: '#22c55e' },
            { label: 'Avg Confidence', value: emails.length ? Math.round(emails.reduce((a, e) => a + (e.confidence || 0), 0) / emails.length * 100) + '%' : '—', color: '#f59e0b' },
          ].map(s => (
            <div key={s.label} style={{ padding: '1rem', background: 'var(--color-bg-card)', borderRadius: 10, border: '1px solid var(--color-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: s.color }}>{s.value}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.25rem' }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Load / search */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        {!loaded ? (
          <button
            onClick={handleLoad}
            disabled={!activeScanId || loading}
            style={{
              padding: '0.625rem 1.5rem', borderRadius: 10, fontWeight: 700, cursor: activeScanId ? 'pointer' : 'not-allowed',
              background: activeScanId ? 'var(--color-cyber-blue)' : 'rgba(255,255,255,0.1)',
              color: activeScanId ? '#000' : 'var(--color-text-muted)', border: 'none', fontSize: '0.875rem',
            }}
          >
            {loading ? 'Loading…' : activeScanId ? 'Load Email Intelligence' : 'No active scan'}
          </button>
        ) : (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 10, padding: '0.5rem 0.875rem' }}>
            <Search size={14} color="var(--color-text-muted)" />
            <input
              value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter emails…"
              style={{ background: 'none', border: 'none', outline: 'none', color: 'var(--color-text-primary)', fontSize: '0.875rem', flex: 1 }}
            />
          </div>
        )}
      </div>

      {/* Email cards */}
      {loaded && filtered.length === 0 && (
        <div style={{ textAlign: 'center', color: 'var(--color-text-muted)', padding: '3rem' }}>
          <Mail size={40} style={{ marginBottom: '1rem', opacity: 0.4 }} />
          <div>No email intelligence found. Run a Live scan with Hunter.io API key for email discovery.</div>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
        {filtered.map(f => (
          <EmailCard key={f.id} finding={f} onViewMore={setSelectedFinding} />
        ))}
      </div>

      <div style={{ marginTop: '2rem', padding: '0.875rem 1rem', borderRadius: 8, background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.15)', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
        <Shield size={12} style={{ display: 'inline', marginRight: '0.375rem', color: '#8b5cf6' }} />
        <strong style={{ color: '#8b5cf6' }}>Passive only:</strong> All email data is discovered from public sources only.
        No credential lookup, no breach access, no unauthorized API calls.
      </div>

      {selectedFinding && <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </div>
  );
}
