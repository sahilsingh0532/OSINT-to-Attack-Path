import { GraduationCap, Target, Lightbulb, BookOpen, CheckCircle2 } from 'lucide-react';

export default function Research() {
  return (
    <div className="animate-fade-in" style={{ maxWidth: 900 }}>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Research Insights</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          Academic framing and methodology of this VAPT project.
        </p>
      </div>

      {/* Research Question */}
      <div className="card" style={{ marginBottom: '1.5rem', background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.05), rgba(168, 85, 247, 0.05))' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <Target size={18} color="var(--color-cyber-blue)" />
          <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, color: 'var(--color-cyber-blue)' }}>Research Question</h2>
        </div>
        <p style={{ margin: 0, fontSize: '0.9375rem', color: 'var(--color-text-primary)', lineHeight: 1.7, fontStyle: 'italic' }}>
          Can publicly available OSINT be correlated to identify meaningful attack paths against an organization's external attack surface without directly interacting with its infrastructure?
        </p>
      </div>

      {/* Objectives */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <BookOpen size={18} color="var(--color-cyber-green)" />
          <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>Research Objectives</h2>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {[
            'Automate passive reconnaissance through multiple OSINT sources.',
            'Normalize and correlate heterogeneous OSINT data into a unified graph.',
            'Identify potential attack paths through graph-based analysis.',
            'Prioritize risks using a transparent, multi-factor scoring model.',
            'Generate actionable defensive recommendations for each finding.',
            'Demonstrate that individually harmless OSINT findings become significantly more valuable when correlated together.',
          ].map((obj, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
              <CheckCircle2 size={14} color="var(--color-cyber-green)" style={{ marginTop: 3, flexShrink: 0 }} />
              <span style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>{obj}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Methodology */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <GraduationCap size={18} color="var(--color-cyber-purple)" />
          <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>Methodology</h2>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {[
            { phase: 'Phase 1: Passive OSINT Collection', desc: 'Data is collected from multiple public sources (DNS/RDAP, Certificate Transparency, GitHub, threat intelligence feeds, Ahmia) using only passive techniques — no active scanning, port scanning, or direct interaction with target infrastructure.' },
            { phase: 'Phase 2: Data Normalization', desc: 'Raw data from heterogeneous sources is normalized into a standardized format with confidence scoring and evidence classification (Observed, Inferred, Hypothesized).' },
            { phase: 'Phase 3: Cross-Source Correlation', desc: 'A graph-based correlation engine builds relationships between findings using 12 correlation rules. This is the core intelligence component that transforms individual data points into an attack surface map.' },
            { phase: 'Phase 4: Attack Path Generation', desc: 'Graph traversal algorithms identify potential attack chains from entry points through assets and weaknesses to potential impacts. All paths are labeled as hypotheses requiring authorized validation.' },
            { phase: 'Phase 5: Risk Prioritization', desc: 'A transparent 4-factor risk model (Exposure × Confidence × Exploitability × Impact) scores each finding. This is an academic model, not CVSS.' },
            { phase: 'Phase 6: Defensive Recommendations', desc: 'Automated defensive recommendations are generated for each high-risk finding, categorized by security control type and implementation effort.' },
          ].map((m, i) => (
            <div key={i} style={{ paddingLeft: '1rem', borderLeft: '3px solid var(--color-cyber-purple)' }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.25rem' }}>{m.phase}</div>
              <p style={{ margin: 0, fontSize: '0.8125rem', color: 'var(--color-text-muted)', lineHeight: 1.6 }}>{m.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Novelty */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <Lightbulb size={18} color="var(--color-cyber-orange)" />
          <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>Novelty & Contribution</h2>
        </div>
        <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.7, margin: '0 0 1rem' }}>
          This project's contribution lies in the combination of:
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
          {[
            { title: 'OSINT + Correlation', desc: 'Cross-source data fusion from heterogeneous passive intelligence sources' },
            { title: 'Attack Path Graphs', desc: 'Graph-based attack hypothesis generation from correlated OSINT' },
            { title: 'Risk + Defense', desc: 'Transparent risk scoring with actionable defensive recommendations' },
          ].map((n, i) => (
            <div key={i} style={{ padding: '1rem', background: 'var(--color-bg-secondary)', borderRadius: 8, border: '1px solid var(--color-border)' }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.375rem', color: 'var(--color-cyber-orange)' }}>{n.title}</div>
              <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text-muted)', lineHeight: 1.5 }}>{n.desc}</p>
            </div>
          ))}
        </div>
        <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', lineHeight: 1.7, margin: '1rem 0 0' }}>
          Rather than simply performing reconnaissance, this framework emphasizes the complete pipeline: <strong style={{ color: 'var(--color-text-primary)' }}>Collect → Normalize → Correlate → Reason → Prioritize → Defend</strong>.
          The key demonstration is showing how several individually harmless OSINT findings can become significantly more valuable when correlated together.
        </p>
      </div>

      {/* Technology Stack */}
      <div className="card">
        <h2 style={{ margin: '0 0 0.75rem', fontSize: '1rem', fontWeight: 700 }}>Technology Stack</h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div>
            <h4 style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.5rem' }}>Frontend</h4>
            <ul style={{ margin: 0, paddingLeft: '1rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 2 }}>
              <li>React + Vite</li>
              <li>TailwindCSS v4</li>
              <li>Cytoscape.js (Graph Visualization)</li>
              <li>Recharts (Charts)</li>
              <li>Zustand (State Management)</li>
              <li>Lucide React (Icons)</li>
            </ul>
          </div>
          <div>
            <h4 style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.5rem' }}>Backend</h4>
            <ul style={{ margin: 0, paddingLeft: '1rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 2 }}>
              <li>Python + FastAPI</li>
              <li>SQLAlchemy (Async) + SQLite</li>
              <li>NetworkX (Graph Analysis)</li>
              <li>Pydantic (Validation)</li>
              <li>HTTPX (HTTP Client)</li>
              <li>dnspython (DNS Lookups)</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
