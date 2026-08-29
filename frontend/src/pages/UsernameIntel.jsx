import { useState } from 'react';
import { User, Search, GitBranch, Globe, ExternalLink, CheckCircle } from 'lucide-react';
import useScanStore from '../stores/scanStore';
import { getUsernames } from '../services/api';
import EvidenceModal from '../components/common/EvidenceModal';

function PlatformBadge({ platform }) {
  const icons = { github: <GitBranch size={10} />, organization: <Globe size={10} /> };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
      padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.625rem', fontWeight: 600,
      background: 'rgba(139,92,246,0.1)', color: '#8b5cf6',
      border: '1px solid rgba(139,92,246,0.2)', textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>
      {icons[platform.toLowerCase()] || null}
      {platform}
    </span>
  );
}

function IdentityCard({ finding, onViewMore }) {
  const sources = finding.sources || [finding.source];
  const isGitHub = sources.includes('github') || finding.value?.includes('github');
  const raw = finding.raw_data || {};
  const login = raw.login || finding.value?.replace('github_org:', '').replace('github_user:', '');
  const profileUrl = finding.external_url;

  return (
    <div style={{
      background: 'var(--color-bg-card)', border: '1px solid var(--color-border)',
      borderRadius: 12, padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
          <div style={{ width: 44, height: 44, borderRadius: 12, background: 'rgba(139,92,246,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            {isGitHub ? <GitBranch size={20} color="#8b5cf6" /> : <User size={20} color="#8b5cf6" />}
          </div>
          <div>
            <div style={{ fontSize: '0.9375rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>
              {login || finding.value}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.125rem' }}>
              {finding.description?.slice(0, 80)}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.375rem', flexShrink: 0 }}>
          <PlatformBadge platform={raw.type || 'GitHub'} />
        </div>
      </div>

      {/* Stats row */}
      {(raw.public_repos !== undefined || raw.followers !== undefined) && (
        <div style={{ display: 'flex', gap: '1rem', fontSize: '0.8125rem' }}>
          {raw.public_repos !== undefined && (
            <span style={{ color: 'var(--color-text-secondary)' }}>
              <strong style={{ color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)' }}>{raw.public_repos}</strong> repos
            </span>
          )}
          {raw.followers !== undefined && (
            <span style={{ color: 'var(--color-text-secondary)' }}>
              <strong style={{ color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)' }}>{raw.followers}</strong> followers
            </span>
          )}
          {raw.location && (
            <span style={{ color: 'var(--color-text-muted)' }}>📍 {raw.location}</span>
          )}
        </div>
      )}

      {/* Source pills */}
      <div style={{ display: 'flex', gap: '0.375rem', flexWrap: 'wrap' }}>
        {sources.map(s => (
          <span key={s} style={{
            padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.625rem', fontWeight: 600,
            background: 'rgba(0,212,255,0.08)', color: 'var(--color-cyber-blue)',
            border: '1px solid rgba(0,212,255,0.15)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
          }}>{s}</span>
        ))}
      </div>

      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button
          onClick={() => onViewMore(finding)}
          style={{ padding: '0.375rem 0.875rem', borderRadius: 8, background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.2)', color: '#8b5cf6', fontSize: '0.8125rem', cursor: 'pointer', fontWeight: 600 }}
        >
          View More
        </button>
        {profileUrl && (
          <a
            href={profileUrl} target="_blank" rel="noopener noreferrer"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem', padding: '0.375rem 0.875rem', borderRadius: 8, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--color-border)', color: 'var(--color-text-muted)', fontSize: '0.8125rem', textDecoration: 'none', fontWeight: 600 }}
          >
            <ExternalLink size={12} /> GitHub
          </a>
        )}
      </div>
    </div>
  );
}

export default function UsernameIntel() {
  const { currentScan } = useScanStore();
  const activeScanId = currentScan?.id || null;
  const [identities, setIdentities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [filter, setFilter] = useState('');

  const handleLoad = async () => {
    if (!activeScanId) return;
    setLoading(true);
    try {
      const data = await getUsernames(activeScanId);
      setIdentities(data);
      setLoaded(true);
    } catch {
      setIdentities([]);
    }
    setLoading(false);
  };

  const filtered = identities.filter(i =>
    !filter || i.value?.toLowerCase().includes(filter.toLowerCase()) || i.description?.toLowerCase().includes(filter.toLowerCase())
  );

  const orgs = identities.filter(i => i.raw_data?.type === 'Organization');
  const users = identities.filter(i => i.raw_data?.type !== 'Organization');

  return (
    <div style={{ padding: '2rem', maxWidth: 900, margin: '0 auto' }}>
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(139,92,246,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <User size={20} color="#8b5cf6" />
          </div>
          <h1 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 800 }}>Username Intelligence</h1>
        </div>
        <p style={{ margin: 0, color: 'var(--color-text-muted)', fontSize: '0.875rem' }}>
          Public GitHub organizations and developer profiles associated with the target domain.
          Data collected from public GitHub API only.
        </p>
      </div>

      {loaded && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
          {[
            { label: 'Total Identities', value: identities.length, color: '#8b5cf6' },
            { label: 'Organizations', value: orgs.length, color: 'var(--color-cyber-blue)' },
            { label: 'Developers', value: users.length, color: '#22c55e' },
          ].map(s => (
            <div key={s.label} style={{ padding: '1rem', background: 'var(--color-bg-card)', borderRadius: 10, border: '1px solid var(--color-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: s.color }}>{s.value}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.25rem' }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem' }}>
        {!loaded ? (
          <button
            onClick={handleLoad} disabled={!activeScanId || loading}
            style={{
              padding: '0.625rem 1.5rem', borderRadius: 10, fontWeight: 700,
              cursor: activeScanId ? 'pointer' : 'not-allowed',
              background: activeScanId ? '#8b5cf6' : 'rgba(255,255,255,0.1)',
              color: activeScanId ? '#fff' : 'var(--color-text-muted)', border: 'none', fontSize: '0.875rem',
            }}
          >
            {loading ? 'Loading…' : activeScanId ? 'Load Username Intelligence' : 'No active scan'}
          </button>
        ) : (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 10, padding: '0.5rem 0.875rem' }}>
            <Search size={14} color="var(--color-text-muted)" />
            <input
              value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter identities…"
              style={{ background: 'none', border: 'none', outline: 'none', color: 'var(--color-text-primary)', fontSize: '0.875rem', flex: 1 }}
            />
          </div>
        )}
      </div>

      {loaded && filtered.length === 0 && (
        <div style={{ textAlign: 'center', color: 'var(--color-text-muted)', padding: '3rem' }}>
          <GitBranch size={40} style={{ marginBottom: '1rem', opacity: 0.4 }} />
          <div>No username intelligence found. Run a Live scan with GitHub token for identity discovery.</div>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
        {filtered.map(f => <IdentityCard key={f.id} finding={f} onViewMore={setSelectedFinding} />)}
      </div>

      {selectedFinding && <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </div>
  );
}
