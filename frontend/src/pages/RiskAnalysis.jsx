import { useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import useScanStore from '../stores/scanStore';
import { getRiskColor, getRiskBg, formatConfidence } from '../utils/helpers';

export default function RiskAnalysis() {
  const { riskScores, riskSummary, findings } = useScanStore();
  const [selected, setSelected] = useState(null);

  // Find finding for each risk score
  const enrichedScores = riskScores.map(rs => {
    const finding = findings.find(f => f.id === rs.finding_id);
    return { ...rs, finding };
  });

  const distributionData = riskSummary ? [
    { name: 'Critical', value: riskSummary.critical_count, color: '#dc2626' },
    { name: 'Very High', value: riskSummary.very_high_count, color: '#ea580c' },
    { name: 'High', value: riskSummary.high_count, color: '#f59e0b' },
    { name: 'Medium', value: riskSummary.medium_count, color: '#3b82f6' },
    { name: 'Low', value: riskSummary.low_count, color: '#22c55e' },
  ].filter(d => d.value > 0) : [];

  const factorData = enrichedScores.map(rs => ({
    name: rs.finding?.title?.slice(0, 20) || 'Finding',
    Exposure: rs.exposure,
    Confidence: rs.confidence,
    Exploitability: rs.exploitability,
    Impact: rs.impact,
  }));

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Risk Analysis</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          Risk prioritization using the 4-factor model: Exposure × Confidence × Exploitability × Impact
        </p>
      </div>

      {/* Summary Cards */}
      {riskSummary && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.75rem', marginBottom: '1.5rem' }}>
          <div className="card" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.375rem' }}>Overall Score</div>
            <div style={{ fontSize: '2rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: getRiskColor(riskSummary.overall_level) }}>
              {Math.round(riskSummary.overall_score)}
            </div>
            <span className={getRiskBg(riskSummary.overall_level)} style={{ padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.625rem', fontWeight: 600 }}>
              {riskSummary.overall_level}
            </span>
          </div>
          {[
            { label: 'Critical / Very High', value: (riskSummary.critical_count || 0) + (riskSummary.very_high_count || 0), color: '#dc2626' },
            { label: 'High', value: riskSummary.high_count || 0, color: '#f59e0b' },
            { label: 'Medium / Low', value: (riskSummary.medium_count || 0) + (riskSummary.low_count || 0), color: '#3b82f6' },
          ].map(c => (
            <div key={c.label} className="card" style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.375rem' }}>{c.label}</div>
              <div style={{ fontSize: '2rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: c.color }}>{c.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
        <div className="card">
          <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, margin: '0 0 1rem', color: 'var(--color-text-secondary)' }}>Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={distributionData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={75} paddingAngle={3}>
                {distributionData.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: '0.75rem', color: 'var(--color-text-primary)' }} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            {distributionData.map(d => (
              <span key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: d.color, display: 'inline-block' }} />
                {d.name} ({d.value})
              </span>
            ))}
          </div>
        </div>

        <div className="card">
          <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, margin: '0 0 1rem', color: 'var(--color-text-secondary)' }}>Risk Factors Breakdown</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={factorData} margin={{ left: 0, right: 16 }}>
              <XAxis dataKey="name" tick={{ fill: 'var(--color-text-muted)', fontSize: 9 }} />
              <YAxis domain={[0, 10]} tick={{ fill: 'var(--color-text-muted)', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: '0.75rem', color: 'var(--color-text-primary)' }} />
              <Bar dataKey="Exposure" fill="#00d4ff" radius={[2, 2, 0, 0]} />
              <Bar dataKey="Exploitability" fill="#f59e0b" radius={[2, 2, 0, 0]} />
              <Bar dataKey="Impact" fill="#ef4444" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Risk Findings Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--color-border)' }}>
          <h3 style={{ margin: 0, fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-text-secondary)' }}>Risk Findings</h3>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Evidence</th>
              <th>Exposure</th>
              <th>Confidence</th>
              <th>Exploitability</th>
              <th>Impact</th>
              <th>Score</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {enrichedScores.map(rs => (
              <tr key={rs.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(selected === rs.id ? null : rs.id)}>
                <td style={{ fontWeight: 500, fontSize: '0.8125rem', maxWidth: 200 }}>{rs.finding?.title || 'Finding'}</td>
                <td style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {rs.finding?.evidence || '—'}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', textAlign: 'center' }}>{rs.exposure}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', textAlign: 'center' }}>{rs.confidence}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', textAlign: 'center' }}>{rs.exploitability}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', textAlign: 'center' }}>{rs.impact}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9375rem', fontWeight: 700, textAlign: 'center', color: getRiskColor(rs.risk_level) }}>
                  {rs.composite_score}
                </td>
                <td>
                  <span className={getRiskBg(rs.risk_level)} style={{ padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.6875rem', fontWeight: 600 }}>
                    {rs.risk_level}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Expanded rationale */}
      {selected && enrichedScores.find(rs => rs.id === selected) && (
        <div className="card animate-slide-in" style={{ marginTop: '0.75rem' }}>
          <h4 style={{ fontSize: '0.8125rem', fontWeight: 600, margin: '0 0 0.5rem' }}>Risk Rationale</h4>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', margin: 0, lineHeight: 1.6 }}>
            {enrichedScores.find(rs => rs.id === selected)?.rationale}
          </p>
        </div>
      )}

      {/* Disclaimer */}
      <div style={{
        marginTop: '1rem', padding: '0.75rem 1rem',
        background: 'rgba(59, 130, 246, 0.06)', border: '1px solid rgba(59, 130, 246, 0.15)',
        borderRadius: 8, fontSize: '0.6875rem', color: 'var(--color-text-muted)',
      }}>
        This is an academic risk-prioritization model and is not CVSS. Score = (Exposure × Confidence × Exploitability × Impact) / 100, normalized to 0–100.
      </div>
    </div>
  );
}
