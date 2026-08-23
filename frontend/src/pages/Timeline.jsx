import useScanStore from '../stores/scanStore';
import { getNodeColor, formatDate, formatConfidence, capitalize } from '../utils/helpers';

export default function Timeline() {
  const { timeline } = useScanStore();

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>OSINT Timeline</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          Chronological view of OSINT discoveries — demonstrating how the attack surface evolves over time.
        </p>
      </div>

      {timeline.length === 0 ? (
        <p style={{ textAlign: 'center', color: 'var(--color-text-muted)', padding: '4rem' }}>Run a scan to generate the OSINT timeline.</p>
      ) : (
        <div style={{ position: 'relative', paddingLeft: '3rem' }}>
          {/* Timeline line */}
          <div className="timeline-line" />

          {timeline.map((event, idx) => {
            const color = getNodeColor(event.finding_type);
            const prevDate = idx > 0 ? formatDate(timeline[idx - 1].timestamp) : null;
            const curDate = formatDate(event.timestamp);
            const showDateHeader = curDate !== prevDate;

            return (
              <div key={event.id}>
                {showDateHeader && (
                  <div style={{
                    position: 'relative',
                    marginBottom: '0.5rem',
                    marginTop: idx > 0 ? '1.5rem' : 0,
                    paddingLeft: '1.5rem',
                  }}>
                    <div style={{
                      fontSize: '0.8125rem', fontWeight: 700, fontFamily: 'var(--font-mono)',
                      color: 'var(--color-cyber-blue)',
                    }}>
                      {curDate}
                    </div>
                  </div>
                )}

                <div style={{
                  position: 'relative',
                  marginBottom: '0.75rem',
                  paddingLeft: '1.5rem',
                }}>
                  {/* Dot */}
                  <div className="timeline-dot" style={{ borderColor: color, top: '0.375rem' }} />

                  {/* Content */}
                  <div className="card" style={{ padding: '0.75rem 1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <div style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.25rem' }}>
                          {event.title}
                        </div>
                        <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text-muted)', lineHeight: 1.5 }}>
                          {event.description?.slice(0, 120)}{event.description?.length > 120 ? '...' : ''}
                        </p>
                      </div>
                      <div style={{ display: 'flex', gap: '0.375rem', flexShrink: 0, marginLeft: '0.75rem' }}>
                        <span style={{
                          fontSize: '0.5625rem', padding: '0.0625rem 0.375rem', borderRadius: 9999,
                          background: `${color}20`, color, fontWeight: 500,
                        }}>
                          {event.finding_type}
                        </span>
                        <span style={{
                          fontSize: '0.5625rem', padding: '0.0625rem 0.375rem', borderRadius: 9999,
                          background: event.observation_type === 'observed' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(59, 130, 246, 0.1)',
                          color: event.observation_type === 'observed' ? '#22c55e' : '#3b82f6',
                          fontWeight: 500,
                        }}>
                          {event.observation_type}
                        </span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '1rem', marginTop: '0.375rem', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                      <span>Source: {event.source}</span>
                      <span>Confidence: {formatConfidence(event.confidence)}</span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
