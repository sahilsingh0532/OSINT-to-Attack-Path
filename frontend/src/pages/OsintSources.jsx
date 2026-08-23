import { useState } from 'react';
import { Database, Search, Filter } from 'lucide-react';
import useScanStore from '../stores/scanStore';
import { formatDate, formatConfidence, capitalize } from '../utils/helpers';

export default function OsintSources() {
  const { findings } = useScanStore();
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');

  const types = [...new Set(findings.map(f => f.finding_type))];
  const filtered = findings.filter(f => {
    const matchesSearch = !filter || f.value.toLowerCase().includes(filter.toLowerCase()) || (f.title && f.title.toLowerCase().includes(filter.toLowerCase()));
    const matchesType = typeFilter === 'all' || f.finding_type === typeFilter;
    return matchesSearch && matchesType;
  });

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>OSINT Sources</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          All collected findings from passive reconnaissance — {findings.length} total records.
        </p>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, maxWidth: 400 }}>
          <Search size={14} color="var(--color-text-muted)" />
          <input className="input-field" style={{ flex: 1 }} placeholder="Search findings..." value={filter} onChange={e => setFilter(e.target.value)} />
        </div>
        <select
          className="input-field"
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          style={{ width: 200 }}
        >
          <option value="all">All Types</option>
          {types.map(t => <option key={t} value={t}>{capitalize(t)}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Title</th>
              <th>Source</th>
              <th>Confidence</th>
              <th>Observation</th>
              <th>Discovered</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(f => (
              <tr key={f.id}>
                <td>
                  <span style={{ fontSize: '0.6875rem', padding: '0.125rem 0.5rem', borderRadius: 9999, background: 'rgba(0, 212, 255, 0.1)', color: 'var(--color-cyber-blue)', fontWeight: 500 }}>
                    {f.finding_type}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.value}
                </td>
                <td style={{ fontSize: '0.8125rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.title || '—'}
                </td>
                <td style={{ color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>{f.source}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>{formatConfidence(f.confidence)}</td>
                <td>
                  <span style={{
                    fontSize: '0.6875rem', padding: '0.125rem 0.5rem', borderRadius: 9999,
                    background: f.observation_type === 'observed' ? 'rgba(34, 197, 94, 0.1)' : f.observation_type === 'inferred' ? 'rgba(59, 130, 246, 0.1)' : 'rgba(245, 158, 11, 0.1)',
                    color: f.observation_type === 'observed' ? '#22c55e' : f.observation_type === 'inferred' ? '#3b82f6' : '#f59e0b',
                    fontWeight: 500,
                  }}>
                    {f.observation_type}
                  </span>
                </td>
                <td style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>{formatDate(f.discovered_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--color-text-muted)' }}>No findings match your filters.</div>
        )}
      </div>
    </div>
  );
}
