import { useState } from 'react';
import { Route, ChevronDown, ChevronUp, AlertTriangle, ShieldCheck } from 'lucide-react';
import useScanStore from '../stores/scanStore';
import { getRiskColor, getRiskBg } from '../utils/helpers';

export default function AttackPaths() {
  const { attackPaths } = useScanStore();
  const [expanded, setExpanded] = useState(null);

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Attack Path Hypotheses</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          {attackPaths.length} potential attack paths identified from correlated OSINT data.
        </p>
      </div>

      {attackPaths.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--color-text-muted)' }}>
          Run a scan to generate attack path hypotheses.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {attackPaths.map((ap, idx) => (
            <div key={ap.id} className="card" style={{ padding: 0, overflow: 'hidden' }}>
              {/* Header */}
              <div
                style={{
                  padding: '1rem 1.25rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1rem',
                  cursor: 'pointer',
                }}
                onClick={() => setExpanded(expanded === ap.id ? null : ap.id)}
              >
                <div style={{
                  width: 40, height: 40, borderRadius: 8,
                  background: `${getRiskColor(ap.risk_level)}15`,
                  border: `1px solid ${getRiskColor(ap.risk_level)}30`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '0.875rem', fontWeight: 700, fontFamily: 'var(--font-mono)',
                  color: getRiskColor(ap.risk_level),
                  flexShrink: 0,
                }}>
                  #{idx + 1}
                </div>

                <div style={{ flex: 1 }}>
                  <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 600 }}>{ap.title}</h3>
                  <p style={{ margin: '0.25rem 0 0', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>{ap.description}</p>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '1.25rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: getRiskColor(ap.risk_level) }}>
                      {ap.risk_score}
                    </div>
                    <span className={getRiskBg(ap.risk_level)} style={{ padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.625rem', fontWeight: 600 }}>
                      {ap.risk_level}
                    </span>
                  </div>
                  {expanded === ap.id ? <ChevronUp size={16} color="var(--color-text-muted)" /> : <ChevronDown size={16} color="var(--color-text-muted)" />}
                </div>
              </div>

              {/* Expanded Content */}
              {expanded === ap.id && (
                <div style={{ padding: '0 1.25rem 1.25rem', borderTop: '1px solid var(--color-border)' }}>
                  {/* Validation Warning */}
                  <div style={{
                    margin: '1rem 0',
                    padding: '0.625rem 1rem',
                    background: 'rgba(245, 158, 11, 0.08)',
                    border: '1px solid rgba(245, 158, 11, 0.2)',
                    borderRadius: 8,
                    fontSize: '0.75rem',
                    color: '#f59e0b',
                    display: 'flex', alignItems: 'center', gap: '0.5rem',
                  }}>
                    <AlertTriangle size={14} />
                    <strong>Potential Attack Path — Requires Authorized Validation</strong>
                  </div>

                  {/* Attack Chain */}
                  <div style={{ marginBottom: '1rem' }}>
                    <h4 style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
                      Attack Chain
                    </h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {ap.nodes.map((node, ni) => (
                        <div key={node.id} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                          <div style={{
                            width: 28, height: 28, borderRadius: '50%',
                            background: node.node_type === 'entry' ? 'var(--color-cyber-blue)' :
                                        node.node_type === 'asset' ? 'var(--color-cyber-teal)' :
                                        node.node_type === 'weakness' ? 'var(--color-cyber-orange)' : 'var(--color-cyber-red)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontSize: '0.6875rem', fontWeight: 700, color: '#0a0e1a',
                            flexShrink: 0,
                          }}>
                            {ni + 1}
                          </div>
                          {ni < ap.nodes.length - 1 && (
                            <div style={{ position: 'absolute', left: '0.825rem', top: '2.25rem', width: 2, height: 20, background: 'var(--color-border)' }} />
                          )}
                          <div>
                            <div style={{ fontSize: '0.8125rem', fontWeight: 600 }}>{node.label}</div>
                            {node.description && (
                              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>{node.description}</div>
                            )}
                          </div>
                          <span style={{
                            marginLeft: 'auto', fontSize: '0.5625rem', padding: '0.0625rem 0.375rem', borderRadius: 9999,
                            background: 'rgba(0, 212, 255, 0.1)', color: 'var(--color-cyber-blue)', fontWeight: 500, flexShrink: 0,
                          }}>
                            {node.node_type}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Hypothesis */}
                  <div style={{ marginBottom: '1rem' }}>
                    <h4 style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>
                      Attack Hypothesis
                    </h4>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', margin: 0, lineHeight: 1.6 }}>
                      {ap.hypothesis}
                    </p>
                  </div>

                  {/* Entry & Target */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                    <div style={{ padding: '0.75rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                      <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.25rem' }}>Entry Point</div>
                      <div style={{ fontSize: '0.8125rem', fontFamily: 'var(--font-mono)' }}>{ap.entry_point}</div>
                    </div>
                    <div style={{ padding: '0.75rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                      <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.25rem' }}>Target Asset</div>
                      <div style={{ fontSize: '0.8125rem', fontFamily: 'var(--font-mono)' }}>{ap.target_asset}</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
