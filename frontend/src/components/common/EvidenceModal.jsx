import { useState, useEffect } from 'react';
import { X, Shield, CheckCircle, Circle, AlertTriangle, Clock, ExternalLink, ChevronDown, ChevronUp, Info } from 'lucide-react';

const OBSERVATION_COLORS = {
  observed: { bg: 'rgba(34,197,94,0.12)', color: '#22c55e', label: 'OBSERVED' },
  inferred: { bg: 'rgba(59,130,246,0.12)', color: '#3b82f6', label: 'INFERRED' },
  hypothesized: { bg: 'rgba(245,158,11,0.12)', color: '#f59e0b', label: 'HYPOTHESIZED' },
};

function ConfidenceBar({ value }) {
  const pct = Math.round(value * 100);
  const color = pct >= 85 ? '#22c55e' : pct >= 65 ? '#f59e0b' : '#ef4444';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
      <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 9999, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 9999, transition: 'width 0.6s ease' }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem', fontWeight: 700, color, minWidth: 40 }}>{pct}%</span>
    </div>
  );
}

function SourceBadge({ source, found }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: '0.5rem',
      padding: '0.375rem 0.75rem', borderRadius: 8,
      background: found ? 'rgba(34,197,94,0.08)' : 'rgba(255,255,255,0.04)',
      border: `1px solid ${found ? 'rgba(34,197,94,0.2)' : 'rgba(255,255,255,0.06)'}`,
      fontSize: '0.8125rem',
    }}>
      {found
        ? <CheckCircle size={12} color="#22c55e" />
        : <Circle size={12} color="#6b7280" />
      }
      <span style={{ color: found ? '#e2e8f0' : '#6b7280', fontFamily: 'var(--font-mono)' }}>{source}</span>
    </div>
  );
}

export default function EvidenceModal({ finding, onClose }) {
  const [expandedSource, setExpandedSource] = useState(null);
  if (!finding) return null;

  const sources = finding.sources || [finding.source];
  const sourceCount = finding.source_count || sources.length;
  const totalQueried = finding.total_queried || sourceCount;
  const agreement = finding.source_agreement || 1;
  const confidencePct = Math.round((finding.confidence || 0) * 100);
  const obs = OBSERVATION_COLORS[finding.observation_type] || OBSERVATION_COLORS.observed;
  const evidencePerSource = finding.evidence_per_source || [];

  const formatDate = (d) => {
    if (!d) return 'N/A';
    try { return new Date(d).toLocaleDateString('en-IN', { year: 'numeric', month: 'short', day: 'numeric' }); }
    catch { return d; }
  };

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 1000,
        background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--color-bg-card)',
          border: '1px solid var(--color-border)',
          borderRadius: 16, width: '100%', maxWidth: 700,
          maxHeight: '90vh', overflowY: 'auto',
          boxShadow: '0 25px 80px rgba(0,0,0,0.6)',
        }}
      >
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
          padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--color-border)',
          position: 'sticky', top: 0, background: 'var(--color-bg-card)', zIndex: 2,
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem' }}>
              <span style={{
                fontSize: '0.625rem', padding: '0.125rem 0.5rem', borderRadius: 9999,
                background: 'rgba(0,212,255,0.1)', color: 'var(--color-cyber-blue)',
                fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
              }}>{finding.finding_type}</span>
              <span style={{
                fontSize: '0.625rem', padding: '0.125rem 0.5rem', borderRadius: 9999,
                background: obs.bg, color: obs.color, fontWeight: 700, textTransform: 'uppercase',
              }}>{obs.label}</span>
            </div>
            <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>
              {finding.value?.length > 80 ? finding.value.slice(0, 80) + '…' : finding.value}
            </h2>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-muted)', padding: '0.25rem' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

          {/* Confidence + Source Agreement */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div style={{ padding: '1rem', background: 'rgba(0,212,255,0.04)', border: '1px solid rgba(0,212,255,0.12)', borderRadius: 10 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.5rem' }}>Confidence</div>
              <ConfidenceBar value={finding.confidence || 0} />
              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', marginTop: '0.375rem' }}>
                Based on {sourceCount} independent source{sourceCount !== 1 ? 's' : ''}
              </div>
            </div>
            <div style={{ padding: '1rem', background: 'rgba(34,197,94,0.04)', border: '1px solid rgba(34,197,94,0.12)', borderRadius: 10 }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.5rem' }}>Source Agreement</div>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#22c55e' }}>
                {sourceCount}/{totalQueried}
              </div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                {Math.round(agreement * 100)}% agreement across {totalQueried} queried sources
              </div>
            </div>
          </div>

          {/* Sources discovered by */}
          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.75rem' }}>
              DISCOVERED BY
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {sources.map(src => <SourceBadge key={src} source={src} found />)}
            </div>
          </div>

          {/* Timestamps */}
          <div style={{ display: 'flex', gap: '1rem' }}>
            {finding.first_seen && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
                <Clock size={12} />
                First seen: <strong style={{ color: 'var(--color-text-secondary)' }}>{formatDate(finding.first_seen)}</strong>
              </div>
            )}
            {finding.last_seen && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
                <Clock size={12} />
                Last seen: <strong style={{ color: 'var(--color-text-secondary)' }}>{formatDate(finding.last_seen)}</strong>
              </div>
            )}
          </div>

          {/* Description */}
          {finding.description && (
            <div style={{ padding: '0.875rem 1rem', background: 'rgba(255,255,255,0.03)', borderRadius: 8, border: '1px solid var(--color-border)', fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
              {finding.description}
            </div>
          )}

          {/* Per-source evidence */}
          {evidencePerSource.length > 0 && (
            <div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.75rem' }}>
                SOURCE EVIDENCE
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {evidencePerSource.map((ev, i) => (
                  <div key={i} style={{ border: '1px solid var(--color-border)', borderRadius: 8, overflow: 'hidden' }}>
                    <button
                      onClick={() => setExpandedSource(expandedSource === i ? null : i)}
                      style={{
                        width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                        padding: '0.625rem 0.875rem', background: 'rgba(255,255,255,0.02)',
                        border: 'none', cursor: 'pointer', color: 'var(--color-text-primary)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <CheckCircle size={12} color="#22c55e" />
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', fontWeight: 600 }}>{ev.source}</span>
                        {ev.confidence && (
                          <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                            {Math.round(ev.confidence * 100)}%
                          </span>
                        )}
                        {ev.discovered_at && (
                          <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                            · {formatDate(ev.discovered_at)}
                          </span>
                        )}
                      </div>
                      {expandedSource === i ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>
                    {expandedSource === i && (
                      <div style={{ padding: '0.75rem 0.875rem', borderTop: '1px solid var(--color-border)', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
                        {ev.evidence}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Why This Finding Matters — Academic Section */}
          <div style={{
            padding: '1rem', borderRadius: 10,
            background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.15)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', marginBottom: '0.625rem' }}>
              <Info size={14} color="#8b5cf6" />
              <span style={{ fontSize: '0.6875rem', color: '#8b5cf6', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                Why This Finding Matters
              </span>
            </div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.7 }}>
              <strong>Observed:</strong> {finding.title || finding.value}
              {finding.description && <> — {finding.description.slice(0, 120)}</>}
              <br /><br />
              <strong>Sources that observed it:</strong> {sources.join(', ')}
              <br />
              <strong>Why it matters:</strong> {sourceCount >= 3
                ? `This finding is confirmed by ${sourceCount} independent sources, significantly increasing confidence in its validity. Cross-source agreement reduces false positives and provides a reliable basis for attack path generation.`
                : sourceCount === 2
                ? `Confirmed by ${sourceCount} independent sources. Cross-source validation reduces the likelihood of a false positive.`
                : `Single source observation. Independent verification recommended before attribution.`
              }
              <br /><br />
              <strong>Confidence:</strong> {confidencePct}% — based on source count ({sourceCount}/{totalQueried}), source reliability, and data freshness.
              <br /><br />
              <strong>Defender action:</strong> Review this finding in context of your authorized attack surface. If unexpected, investigate immediately.
            </div>
          </div>

          {/* External link */}
          {finding.external_url && (
            <a
              href={finding.external_url} target="_blank" rel="noopener noreferrer"
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.8125rem', color: 'var(--color-cyber-blue)', textDecoration: 'none' }}
            >
              <ExternalLink size={12} /> View external reference
            </a>
          )}

          {/* Disclaimer */}
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', padding: '0.5rem 0', borderTop: '1px solid var(--color-border)' }}>
            This is a passive OSINT finding. Confidence reflects source agreement, not factual accuracy. Active validation requires authorized VAPT.
          </div>
        </div>
      </div>
    </div>
  );
}
