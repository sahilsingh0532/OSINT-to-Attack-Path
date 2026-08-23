import { useState } from 'react';
import { Sword, ShieldCheck, Eye, Lock } from 'lucide-react';
import useScanStore from '../stores/scanStore';
import { getRiskColor, getRiskBg } from '../utils/helpers';

export default function Defense() {
  const [perspective, setPerspective] = useState('defender');
  const { recommendations, attackPaths, findings, riskScores } = useScanStore();

  const exposures = findings.filter(f => f.finding_type === 'exposure');

  return (
    <div className="animate-fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Defense Center</h1>
          <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
            Attacker vs Defender perspective on the discovered attack surface.
          </p>
        </div>
        {/* Perspective Toggle */}
        <div style={{ display: 'flex', borderRadius: 8, overflow: 'hidden', border: '1px solid var(--color-border)' }}>
          <button
            onClick={() => setPerspective('attacker')}
            style={{
              padding: '0.5rem 1rem', display: 'flex', alignItems: 'center', gap: '0.375rem',
              background: perspective === 'attacker' ? 'rgba(239, 68, 68, 0.15)' : 'var(--color-bg-card)',
              color: perspective === 'attacker' ? '#ef4444' : 'var(--color-text-muted)',
              border: 'none', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 500,
            }}
          >
            <Sword size={14} /> Attacker
          </button>
          <button
            onClick={() => setPerspective('defender')}
            style={{
              padding: '0.5rem 1rem', display: 'flex', alignItems: 'center', gap: '0.375rem',
              background: perspective === 'defender' ? 'rgba(34, 197, 94, 0.15)' : 'var(--color-bg-card)',
              color: perspective === 'defender' ? '#22c55e' : 'var(--color-text-muted)',
              border: 'none', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 500,
            }}
          >
            <ShieldCheck size={14} /> Defender
          </button>
        </div>
      </div>

      {perspective === 'attacker' ? (
        /* ATTACKER VIEW */
        <div>
          <div className="card" style={{ marginBottom: '1rem', background: 'rgba(239, 68, 68, 0.04)', borderColor: 'rgba(239, 68, 68, 0.2)' }}>
            <h3 style={{ margin: '0 0 0.75rem', fontSize: '0.9375rem', fontWeight: 600, color: '#ef4444' }}>
              <Eye size={16} style={{ display: 'inline', marginRight: '0.375rem', verticalAlign: 'text-bottom' }} />
              What can an attacker discover?
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '0.75rem' }}>
              {exposures.map(exp => (
                <div key={exp.id} style={{ padding: '0.75rem', background: 'var(--color-bg-secondary)', borderRadius: 8, border: '1px solid var(--color-border)' }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, marginBottom: '0.375rem' }}>{exp.title}</div>
                  <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text-muted)', lineHeight: 1.5 }}>{exp.description}</p>
                  <div style={{ marginTop: '0.5rem', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                    Confidence: {Math.round(exp.confidence * 100)}%
                  </div>
                </div>
              ))}
            </div>
          </div>

          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, margin: '1.5rem 0 0.75rem', color: '#ef4444' }}>Attack Hypotheses</h3>
          {attackPaths.map((ap, i) => (
            <div key={ap.id} className="card" style={{ marginBottom: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span style={{ fontSize: '1.125rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: getRiskColor(ap.risk_level) }}>
                  {ap.risk_score}
                </span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>{ap.title}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>{ap.entry_point} → {ap.target_asset}</div>
                </div>
                <span className={getRiskBg(ap.risk_level)} style={{ padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.625rem', fontWeight: 600 }}>
                  {ap.risk_level}
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        /* DEFENDER VIEW */
        <div>
          <div className="card" style={{ marginBottom: '1rem', background: 'rgba(34, 197, 94, 0.04)', borderColor: 'rgba(34, 197, 94, 0.2)' }}>
            <h3 style={{ margin: '0 0 0.5rem', fontSize: '0.9375rem', fontWeight: 600, color: '#22c55e' }}>
              <Lock size={16} style={{ display: 'inline', marginRight: '0.375rem', verticalAlign: 'text-bottom' }} />
              What should be fixed first?
            </h3>
            <p style={{ margin: 0, fontSize: '0.8125rem', color: 'var(--color-text-secondary)' }}>
              Recommendations are prioritized by risk severity. Priority 1 = Critical, 4 = Low.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {recommendations.map((rec) => (
              <div key={rec.id} className="card">
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                  <div style={{
                    width: 32, height: 32, borderRadius: 8,
                    background: rec.priority === 1 ? 'rgba(220, 38, 38, 0.15)' : rec.priority === 2 ? 'rgba(245, 158, 11, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                    border: `1px solid ${rec.priority === 1 ? 'rgba(220, 38, 38, 0.3)' : rec.priority === 2 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(59, 130, 246, 0.3)'}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '0.75rem', fontWeight: 700,
                    color: rec.priority === 1 ? '#dc2626' : rec.priority === 2 ? '#f59e0b' : '#3b82f6',
                    flexShrink: 0,
                  }}>
                    P{rec.priority}
                  </div>
                  <div style={{ flex: 1 }}>
                    <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 600 }}>{rec.title}</h3>
                    <p style={{ margin: '0.375rem 0', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
                      {rec.description}
                    </p>
                    {rec.rationale && (
                      <div style={{ padding: '0.5rem 0.75rem', background: 'var(--color-bg-secondary)', borderRadius: 6, fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.5rem' }}>
                        <strong>Why:</strong> {rec.rationale}
                      </div>
                    )}
                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                      <span style={{ fontSize: '0.625rem', padding: '0.125rem 0.375rem', borderRadius: 9999, background: 'rgba(0, 212, 255, 0.1)', color: 'var(--color-cyber-blue)' }}>
                        {rec.category.replace(/_/g, ' ')}
                      </span>
                      <span style={{ fontSize: '0.625rem', padding: '0.125rem 0.375rem', borderRadius: 9999, background: 'rgba(139, 92, 246, 0.1)', color: '#8b5cf6' }}>
                        Effort: {rec.effort}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {recommendations.length === 0 && (
            <p style={{ textAlign: 'center', color: 'var(--color-text-muted)', padding: '2rem' }}>
              Run a scan to generate defensive recommendations.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
