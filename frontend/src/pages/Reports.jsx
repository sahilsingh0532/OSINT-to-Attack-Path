import { useState } from 'react';
import { FileText, Download, Check, Loader2 } from 'lucide-react';
import useScanStore from '../stores/scanStore';

const SECTIONS = [
  { key: 'executive_summary', label: 'Executive Summary' },
  { key: 'scope', label: 'Scope' },
  { key: 'methodology', label: 'Methodology' },
  { key: 'sources', label: 'Passive Reconnaissance Sources' },
  { key: 'findings', label: 'Findings' },
  { key: 'attack_surface', label: 'Attack-Surface Map' },
  { key: 'attack_paths', label: 'Attack Paths' },
  { key: 'risk', label: 'Risk Prioritization' },
  { key: 'evidence', label: 'Evidence' },
  { key: 'recommendations', label: 'Defensive Recommendations' },
  { key: 'limitations', label: 'Limitations' },
  { key: 'conclusion', label: 'Conclusion' },
];

export default function Reports() {
  const { currentScan, report, generateReport } = useScanStore();
  const [generating, setGenerating] = useState(false);
  const [selectedSections, setSelectedSections] = useState(SECTIONS.map(s => s.key));

  const handleGenerate = async () => {
    if (!currentScan?.id) return;
    setGenerating(true);
    await generateReport(currentScan.id);
    setGenerating(false);
  };

  const handleDownload = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `OSINT_Report_${currentScan?.target_domain || 'report'}_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleSection = (key) => {
    setSelectedSections(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    );
  };

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>VAPT / OSINT Report</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          Generate a professional passive reconnaissance report.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '1.5rem' }}>
        {/* Sidebar — Section Selection */}
        <div className="card">
          <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, margin: '0 0 1rem', color: 'var(--color-text-secondary)' }}>Report Sections</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
            {SECTIONS.map(s => (
              <label key={s.key} style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.375rem 0.5rem',
                borderRadius: 6, cursor: 'pointer', fontSize: '0.8125rem',
                background: selectedSections.includes(s.key) ? 'rgba(0, 212, 255, 0.06)' : 'transparent',
                color: selectedSections.includes(s.key) ? 'var(--color-text-primary)' : 'var(--color-text-muted)',
              }}>
                <input type="checkbox" checked={selectedSections.includes(s.key)} onChange={() => toggleSection(s.key)}
                  style={{ accentColor: 'var(--color-cyber-blue)' }} />
                {s.label}
              </label>
            ))}
          </div>

          <button
            className="btn-primary"
            style={{ width: '100%', justifyContent: 'center', marginTop: '1rem' }}
            onClick={handleGenerate}
            disabled={!currentScan || generating}
          >
            {generating ? <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Generating...</> :
              <><FileText size={14} /> Generate Report</>}
          </button>
        </div>

        {/* Report Preview */}
        <div className="card" style={{ maxHeight: 'calc(100vh - 250px)', overflowY: 'auto' }}>
          {!report ? (
            <div style={{ textAlign: 'center', padding: '4rem 2rem', color: 'var(--color-text-muted)' }}>
              <FileText size={48} style={{ marginBottom: '1rem', opacity: 0.3 }} />
              <div style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.5rem' }}>No report generated yet</div>
              <div style={{ fontSize: '0.8125rem' }}>
                {currentScan ? 'Select sections and click "Generate Report".' : 'Run a scan first, then generate a report.'}
              </div>
            </div>
          ) : (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                <div>
                  <h2 style={{ margin: 0, fontSize: '1.125rem', fontWeight: 700 }}>{report.title}</h2>
                  <p style={{ margin: '0.125rem 0 0', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                    {report.subtitle} · Generated: {new Date(report.generated_at).toLocaleString()}
                  </p>
                </div>
                <button className="btn-primary" onClick={handleDownload}>
                  <Download size={14} /> Download JSON
                </button>
              </div>

              <div style={{ fontSize: '0.6875rem', padding: '0.5rem 0.75rem', background: 'rgba(220, 38, 38, 0.06)', border: '1px solid rgba(220, 38, 38, 0.15)', borderRadius: 6, color: '#ef4444', marginBottom: '1.5rem' }}>
                {report.classification}
              </div>

              {/* Executive Summary */}
              {report.executive_summary && (
                <div style={{ marginBottom: '1.5rem' }}>
                  <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--color-cyber-blue)' }}>1. Executive Summary</h3>
                  <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.7, margin: 0 }}>
                    {report.executive_summary.summary}
                  </p>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem', marginTop: '0.75rem' }}>
                    {[
                      { label: 'Findings', value: report.executive_summary.total_findings },
                      { label: 'Relationships', value: report.executive_summary.total_relationships },
                      { label: 'Attack Paths', value: report.executive_summary.total_attack_paths },
                      { label: 'Risk Score', value: `${report.executive_summary.overall_risk_score}/100` },
                    ].map(s => (
                      <div key={s.label} style={{ textAlign: 'center', padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                        <div style={{ fontSize: '0.5625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>{s.label}</div>
                        <div style={{ fontSize: '1rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{s.value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Methodology */}
              {report.methodology && (
                <div style={{ marginBottom: '1.5rem' }}>
                  <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--color-cyber-blue)' }}>2. Methodology</h3>
                  <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.8 }}>
                    {report.methodology.phases.map((p, i) => <li key={i}>{p}</li>)}
                  </ul>
                </div>
              )}

              {/* Risk Analysis */}
              {report.risk_analysis && (
                <div style={{ marginBottom: '1.5rem' }}>
                  <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--color-cyber-blue)' }}>3. Risk Distribution</h3>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    {Object.entries(report.risk_analysis.distribution).map(([level, count]) => (
                      <div key={level} style={{
                        padding: '0.5rem 1rem', borderRadius: 8, textAlign: 'center',
                        background: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)',
                      }}>
                        <div style={{ fontSize: '0.5625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>{level}</div>
                        <div style={{ fontSize: '1.25rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{count}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Conclusion */}
              {report.conclusion && (
                <div style={{ marginBottom: '1rem' }}>
                  <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--color-cyber-blue)' }}>4. Conclusion</h3>
                  <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.7, margin: 0 }}>
                    {report.conclusion}
                  </p>
                </div>
              )}

              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', padding: '0.75rem', background: 'var(--color-bg-secondary)', borderRadius: 8, marginTop: '1rem' }}>
                {report.disclaimer}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
