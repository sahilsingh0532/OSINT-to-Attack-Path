import { useState, useMemo } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, CartesianGrid, Legend
} from 'recharts';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, Grid, BarChart3, PieChart as PieIcon,
  Search, Info, ChevronDown, ChevronUp, RotateCcw, Filter, Layers, Activity
} from 'lucide-react';
import useScanStore from '../stores/scanStore';
import { getRiskColor, getRiskBg, formatConfidence } from '../utils/helpers';

// NIST SP 800-30 Rev. 1 Scale Tiers
const TIER_LABELS = ['Very Low', 'Low', 'Moderate', 'High', 'Very High'];
const TIER_COLORS = {
  'Very High': '#dc2626',
  'High': '#f59e0b',
  'Moderate': '#3b82f6',
  'Low': '#22c55e',
  'Very Low': '#10b981',
};

// NIST SP 800-30 Rev. 1 Appendix I: 5x5 Risk Assessment Matrix
// Rows: Likelihood (0=Very Low to 4=Very High), Cols: Impact (0=Very Low to 4=Very High)
const NIST_MATRIX_LEVELS = [
  ['Very Low', 'Very Low', 'Very Low', 'Low', 'Low'],         // Very Low Likelihood
  ['Very Low', 'Very Low', 'Low', 'Moderate', 'Moderate'],     // Low Likelihood
  ['Very Low', 'Low', 'Moderate', 'High', 'High'],             // Moderate Likelihood
  ['Low', 'Moderate', 'High', 'High', 'Very High'],            // High Likelihood
  ['Low', 'Moderate', 'High', 'Very High', 'Very High'],       // Very High Likelihood
];

const getScaleTierIndex = (val) => {
  const v = Number(val || 0);
  if (v <= 2.0) return 0;
  if (v <= 4.0) return 1;
  if (v <= 6.0) return 2;
  if (v <= 8.0) return 3;
  return 4;
};

const getLikelihood = (rs) => {
  if (rs.likelihood !== undefined && rs.likelihood !== null) {
    return Number(rs.likelihood);
  }
  const confVal = Number(rs.confidence) > 1 ? Number(rs.confidence) / 100 : Number(rs.confidence || 0.8);
  const confFactor = 0.70 + 0.30 * Math.max(0, Math.min(1, confVal));
  const base = (Number(rs.exposure || 0) + Number(rs.exploitability || 0)) / 2;
  return Math.min(10, Math.max(0, Math.round(base * confFactor * 10) / 10));
};

const getNistTier = (score) => {
  const s = Number(score || 0);
  if (s > 80.0) return 'Very High';
  if (s > 60.0) return 'High';
  if (s > 40.0) return 'Moderate';
  if (s > 20.0) return 'Low';
  return 'Very Low';
};

export default function RiskAnalysis() {
  const { riskScores, riskSummary, findings } = useScanStore();
  const [selected, setSelected] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTier, setSelectedTier] = useState('ALL');
  const [matrixFilter, setMatrixFilter] = useState(null); // { lIndex, iIndex }
  const [chartTab, setChartTab] = useState('top10'); // 'top10', 'distribution', 'categories'

  // Enrich risk scores with findings and computed NIST likelihood
  const enrichedScores = useMemo(() => {
    return riskScores.map(rs => {
      const finding = findings.find(f => f.id === rs.finding_id);
      const likelihood = getLikelihood(rs);
      const nistTier = getNistTier(rs.composite_score);
      const lIndex = getScaleTierIndex(likelihood);
      const iIndex = getScaleTierIndex(rs.impact);
      return {
        ...rs,
        finding,
        likelihood,
        nistTier,
        lIndex,
        iIndex,
      };
    });
  }, [riskScores, findings]);

  // Aggregate metrics
  const avgLikelihood = useMemo(() => {
    if (!enrichedScores.length) return 0;
    const sum = enrichedScores.reduce((acc, s) => acc + s.likelihood, 0);
    return (sum / enrichedScores.length).toFixed(1);
  }, [enrichedScores]);

  const avgImpact = useMemo(() => {
    if (!enrichedScores.length) return 0;
    const sum = enrichedScores.reduce((acc, s) => acc + (s.impact || 0), 0);
    return (sum / enrichedScores.length).toFixed(1);
  }, [enrichedScores]);

  // NIST 5x5 Matrix counts
  const matrixCounts = useMemo(() => {
    const grid = Array(5).fill(0).map(() => Array(5).fill(0));
    enrichedScores.forEach(s => {
      if (grid[s.lIndex] && grid[s.lIndex][s.iIndex] !== undefined) {
        grid[s.lIndex][s.iIndex]++;
      }
    });
    return grid;
  }, [enrichedScores]);

  // Filtered scores based on search, tier button, and 5x5 matrix filter
  const filteredScores = useMemo(() => {
    return enrichedScores.filter(s => {
      if (matrixFilter) {
        if (s.lIndex !== matrixFilter.lIndex || s.iIndex !== matrixFilter.iIndex) {
          return false;
        }
      }
      if (selectedTier !== 'ALL') {
        const normTier = selectedTier.toLowerCase();
        const itemTier = s.nistTier.toLowerCase();
        const itemLevel = (s.risk_level || '').toLowerCase();
        if (normTier === 'critical' || normTier === 'very high') {
          if (itemTier !== 'very high' && itemLevel !== 'critical' && itemLevel !== 'very high') return false;
        } else if (normTier === 'high') {
          if (itemTier !== 'high' && itemLevel !== 'high') return false;
        } else if (normTier === 'moderate' || normTier === 'medium') {
          if (itemTier !== 'moderate' && itemLevel !== 'medium' && itemLevel !== 'moderate') return false;
        } else if (normTier === 'low' || normTier === 'very low') {
          if (itemTier !== 'low' && itemTier !== 'very low' && itemLevel !== 'low') return false;
        }
      }
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        const title = (s.finding?.title || '').toLowerCase();
        const evidence = (s.finding?.evidence || '').toLowerCase();
        const cat = (s.finding?.category || '').toLowerCase();
        const type = (s.finding?.finding_type || '').toLowerCase();
        return title.includes(q) || evidence.includes(q) || cat.includes(q) || type.includes(q);
      }
      return true;
    });
  }, [enrichedScores, matrixFilter, selectedTier, searchTerm]);

  // NIST Tier Distribution data
  const distributionData = useMemo(() => {
    const counts = { 'Very High': 0, 'High': 0, 'Moderate': 0, 'Low': 0, 'Very Low': 0 };
    enrichedScores.forEach(s => {
      counts[s.nistTier] = (counts[s.nistTier] || 0) + 1;
    });
    return [
      { name: 'Very High (80-100)', value: counts['Very High'], color: TIER_COLORS['Very High'], tierKey: 'Very High' },
      { name: 'High (60-80)', value: counts['High'], color: TIER_COLORS['High'], tierKey: 'High' },
      { name: 'Moderate (40-60)', value: counts['Moderate'], color: TIER_COLORS['Moderate'], tierKey: 'Moderate' },
      { name: 'Low (20-40)', value: counts['Low'], color: TIER_COLORS['Low'], tierKey: 'Low' },
      { name: 'Very Low (0-20)', value: counts['Very Low'], color: TIER_COLORS['Very Low'], tierKey: 'Very Low' },
    ].filter(d => d.value > 0);
  }, [enrichedScores]);

  // Top 10 highest risk findings for comparative chart
  const top10Data = useMemo(() => {
    return [...enrichedScores]
      .sort((a, b) => b.composite_score - a.composite_score)
      .slice(0, 10)
      .map(s => ({
        name: (s.finding?.title || 'Finding').slice(0, 18),
        Likelihood: s.likelihood,
        Impact: s.impact,
        'NIST Score': s.composite_score,
      }));
  }, [enrichedScores]);

  // Category average risk breakdown
  const categoryData = useMemo(() => {
    const cats = {};
    enrichedScores.forEach(s => {
      const c = s.finding?.category || 'other';
      if (!cats[c]) cats[c] = { count: 0, sumScore: 0, sumL: 0, sumI: 0 };
      cats[c].count++;
      cats[c].sumScore += s.composite_score;
      cats[c].sumL += s.likelihood;
      cats[c].sumI += s.impact;
    });
    return Object.entries(cats).map(([name, data]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      avgScore: Math.round((data.sumScore / data.count) * 10) / 10,
      avgL: Math.round((data.sumL / data.count) * 10) / 10,
      avgI: Math.round((data.sumI / data.count) * 10) / 10,
    })).sort((a, b) => b.avgScore - a.avgScore);
  }, [enrichedScores]);

  const overallScore = Math.round(riskSummary?.overall_score || 0);
  const overallTier = getNistTier(overallScore);

  return (
    <div className="animate-fade-in" style={{ paddingBottom: '2.5rem' }}>
      {/* Header */}
      <div style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', marginBottom: '0.375rem' }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0, letterSpacing: '-0.02em' }}>
              Risk Analysis
            </h1>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
              background: 'rgba(0, 212, 255, 0.1)', border: '1px solid rgba(0, 212, 255, 0.3)',
              color: 'var(--color-cyber-blue)', fontSize: '0.6875rem', fontWeight: 600,
              padding: '0.2rem 0.55rem', borderRadius: 9999, textTransform: 'uppercase', letterSpacing: '0.04em'
            }}>
              <ShieldCheck size={12} />
              NIST SP 800-30 Rev. 1
            </span>
          </div>
          <p style={{ margin: 0, fontSize: '0.8125rem', color: 'var(--color-text-muted)', maxWidth: 780, lineHeight: 1.5 }}>
            Guide for Conducting Risk Assessments: Threat Event Likelihood (modulated by Exposure, Exploitability, Confidence) × Adverse Impact on a 0–100 semi-quantitative scale.
          </p>
        </div>

        {/* Methodology Formula Pill */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: '0.5rem',
          background: 'var(--color-bg-card)', border: '1px solid var(--color-border)',
          borderRadius: 8, padding: '0.5rem 0.875rem', fontSize: '0.75rem'
        }}>
          <span style={{ color: 'var(--color-text-muted)' }}>Formula:</span>
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyber-blue)', fontWeight: 600 }}>
            Risk = Likelihood (0–10) × Impact (0–10)
          </span>
        </div>
      </div>

      {/* NIST Executive Summary Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.875rem', marginBottom: '1.5rem' }}>
        {/* Overall NIST Risk Score */}
        <div className="card" style={{
          background: 'linear-gradient(135deg, rgba(26, 31, 54, 0.95), rgba(17, 24, 39, 0.95))',
          border: `1px solid ${overallTier === 'High' || overallTier === 'Very High' ? 'rgba(239, 68, 68, 0.3)' : 'var(--color-border)'}`,
          position: 'relative', overflow: 'hidden'
        }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.375rem', display: 'flex', justifyContent: 'space-between' }}>
            <span>NIST Risk Score</span>
            <Activity size={13} color="var(--color-cyber-blue)" />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: getRiskColor(overallTier) }}>
              {overallScore}
            </span>
            <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>/ 100</span>
          </div>
          <div style={{ marginTop: '0.375rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span className={getRiskBg(overallTier)} style={{ padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase' }}>
              {overallTier}
            </span>
            <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>Aggregate Posture</span>
          </div>
        </div>

        {/* Avg Threat Likelihood */}
        <div className="card">
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.375rem', display: 'flex', justifyContent: 'space-between' }}>
            <span>Avg Threat Likelihood</span>
            <span style={{ fontSize: '0.625rem', color: 'var(--color-cyber-orange)', fontFamily: 'var(--font-mono)' }}>0–10 Scale</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.375rem' }}>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#f59e0b' }}>
              {avgLikelihood}
            </span>
            <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>/ 10</span>
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', marginTop: '0.375rem' }}>
            Modulated by Exposure & Exploitability
          </div>
        </div>

        {/* Avg Threat Impact */}
        <div className="card">
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.375rem', display: 'flex', justifyContent: 'space-between' }}>
            <span>Avg Adverse Impact</span>
            <span style={{ fontSize: '0.625rem', color: 'var(--color-cyber-red)', fontFamily: 'var(--font-mono)' }}>0–10 Scale</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.375rem' }}>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#ef4444' }}>
              {avgImpact}
            </span>
            <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>/ 10</span>
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', marginTop: '0.375rem' }}>
            Potential operational & data harm
          </div>
        </div>

        {/* High & Critical Count */}
        <div className="card">
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.375rem', display: 'flex', justifyContent: 'space-between' }}>
            <span>High & Critical Threats</span>
            <AlertTriangle size={13} color="#f59e0b" />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#ef4444' }}>
              {(riskSummary?.critical_count || 0) + (riskSummary?.very_high_count || 0) + (riskSummary?.high_count || 0)}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
              (Score &gt; 60)
            </span>
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#f59e0b', marginTop: '0.375rem', fontWeight: 500 }}>
            Prioritize for immediate mitigation
          </div>
        </div>

        {/* Total Findings Evaluated */}
        <div className="card">
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.375rem', display: 'flex', justifyContent: 'space-between' }}>
            <span>Total Assessed</span>
            <Layers size={13} color="var(--color-text-muted)" />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
            <span style={{ fontSize: '2.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--color-cyber-blue)' }}>
              {enrichedScores.length}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>findings</span>
          </div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', marginTop: '0.375rem' }}>
            100% mapped into NIST 5×5 Matrix
          </div>
        </div>
      </div>

      {/* Main Analysis Section: NIST 5x5 Matrix & Visualizations */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 1.15fr) 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
        {/* Left: NIST SP 800-30 5x5 Risk Assessment Matrix */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.875rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Grid size={15} color="var(--color-cyber-blue)" />
                <h3 style={{ fontSize: '0.875rem', fontWeight: 700, margin: 0, color: 'var(--color-text-primary)' }}>
                  NIST SP 800-30 5×5 Risk Assessment Matrix
                </h3>
              </div>
              <p style={{ margin: '0.125rem 0 0', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                Click any cell to filter findings by Threat Likelihood × Adverse Impact quadrant
              </p>
            </div>
            {matrixFilter && (
              <button
                onClick={() => setMatrixFilter(null)}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
                  fontSize: '0.6875rem', color: 'var(--color-cyber-blue)',
                  background: 'rgba(0, 212, 255, 0.1)', border: '1px solid rgba(0, 212, 255, 0.25)',
                  padding: '0.2rem 0.5rem', borderRadius: 4, cursor: 'pointer'
                }}
              >
                <RotateCcw size={11} /> Reset Filter
              </button>
            )}
          </div>

          {/* 5x5 Matrix Heatmap Grid */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              {/* Y-axis Label */}
              <div style={{
                writingMode: 'vertical-rl', transform: 'rotate(180deg)',
                textAlign: 'center', fontSize: '0.6875rem', fontWeight: 600,
                color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em'
              }}>
                Threat Event Likelihood →
              </div>

              {/* Grid Content */}
              <div style={{ flex: 1 }}>
                <div style={{ display: 'grid', gridTemplateRows: 'repeat(5, 1fr)', gap: '4px' }}>
                  {[4, 3, 2, 1, 0].map(lIndex => (
                    <div key={lIndex} style={{ display: 'grid', gridTemplateColumns: '70px repeat(5, 1fr)', gap: '4px', alignItems: 'center' }}>
                      {/* Row Label (Likelihood tier) */}
                      <span style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)', textAlign: 'right', paddingRight: '0.25rem', whiteSpace: 'nowrap' }}>
                        {TIER_LABELS[lIndex]}
                      </span>

                      {/* 5 Cells for this row */}
                      {[0, 1, 2, 3, 4].map(iIndex => {
                        const cellLevel = NIST_MATRIX_LEVELS[lIndex][iIndex];
                        const count = matrixCounts[lIndex][iIndex];
                        const isSelected = matrixFilter && matrixFilter.lIndex === lIndex && matrixFilter.iIndex === iIndex;
                        const cellColor = TIER_COLORS[cellLevel];

                        return (
                          <div
                            key={iIndex}
                            onClick={() => {
                              if (isSelected) setMatrixFilter(null);
                              else setMatrixFilter({ lIndex, iIndex, level: cellLevel });
                            }}
                            title={`Likelihood: ${TIER_LABELS[lIndex]} | Impact: ${TIER_LABELS[iIndex]} → NIST Risk: ${cellLevel} (${count} findings)`}
                            style={{
                              height: '42px',
                              borderRadius: 6,
                              display: 'flex',
                              flexDirection: 'column',
                              alignItems: 'center',
                              justifyContent: 'center',
                              cursor: 'pointer',
                              background: isSelected
                                ? `${cellColor}40`
                                : count > 0
                                  ? `${cellColor}22`
                                  : 'rgba(255, 255, 255, 0.02)',
                              border: isSelected
                                ? `2px solid ${cellColor}`
                                : count > 0
                                  ? `1px solid ${cellColor}66`
                                  : '1px solid rgba(255, 255, 255, 0.05)',
                              transition: 'all 0.15s ease',
                              position: 'relative'
                            }}
                          >
                            <span style={{
                              fontSize: count > 0 ? '0.875rem' : '0.6875rem',
                              fontWeight: count > 0 ? 800 : 400,
                              fontFamily: 'var(--font-mono)',
                              color: count > 0 ? cellColor : 'var(--color-text-muted)'
                            }}>
                              {count}
                            </span>
                            <span style={{ fontSize: '0.5625rem', color: count > 0 ? 'var(--color-text-primary)' : 'transparent', textTransform: 'uppercase', lineHeight: 1 }}>
                              {cellLevel.slice(0, 3)}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  ))}

                  {/* X-axis Column Headers (Impact Tiers) */}
                  <div style={{ display: 'grid', gridTemplateColumns: '70px repeat(5, 1fr)', gap: '4px', marginTop: '2px' }}>
                    <div />
                    {[0, 1, 2, 3, 4].map(iIndex => (
                      <span key={iIndex} style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textAlign: 'center', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {TIER_LABELS[iIndex]}
                      </span>
                    ))}
                  </div>
                </div>

                {/* X-axis Label */}
                <div style={{ textAlign: 'center', fontSize: '0.6875rem', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '0.5rem' }}>
                  Threat Event Adverse Impact →
                </div>
              </div>
            </div>
          </div>

          {/* Matrix Legend */}
          <div style={{
            display: 'flex', justifyContent: 'center', gap: '0.75rem', flexWrap: 'wrap',
            paddingTop: '0.75rem', borderTop: '1px solid var(--color-border)', marginTop: '0.75rem'
          }}>
            {['Very High', 'High', 'Moderate', 'Low', 'Very Low'].map(lvl => (
              <span key={lvl} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: TIER_COLORS[lvl] }} />
                {lvl}
              </span>
            ))}
          </div>
        </div>

        {/* Right: Charts with Interactive Tabs */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.875rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <h3 style={{ fontSize: '0.875rem', fontWeight: 700, margin: 0, color: 'var(--color-text-primary)' }}>
              Risk Analytics &amp; Breakdown
            </h3>
            {/* View Switcher Tabs */}
            <div style={{ display: 'flex', background: 'var(--color-bg-input)', padding: '2px', borderRadius: 6, border: '1px solid var(--color-border)' }}>
              <button
                onClick={() => setChartTab('top10')}
                style={{
                  background: chartTab === 'top10' ? 'var(--color-bg-card)' : 'transparent',
                  color: chartTab === 'top10' ? 'var(--color-cyber-blue)' : 'var(--color-text-muted)',
                  border: 'none', borderRadius: 4, padding: '0.25rem 0.5rem', fontSize: '0.6875rem', fontWeight: 600, cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: '0.25rem'
                }}
              >
                <BarChart3 size={12} /> Top Threats
              </button>
              <button
                onClick={() => setChartTab('distribution')}
                style={{
                  background: chartTab === 'distribution' ? 'var(--color-bg-card)' : 'transparent',
                  color: chartTab === 'distribution' ? 'var(--color-cyber-blue)' : 'var(--color-text-muted)',
                  border: 'none', borderRadius: 4, padding: '0.25rem 0.5rem', fontSize: '0.6875rem', fontWeight: 600, cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: '0.25rem'
                }}
              >
                <PieIcon size={12} /> Tier Distribution
              </button>
              <button
                onClick={() => setChartTab('categories')}
                style={{
                  background: chartTab === 'categories' ? 'var(--color-bg-card)' : 'transparent',
                  color: chartTab === 'categories' ? 'var(--color-cyber-blue)' : 'var(--color-text-muted)',
                  border: 'none', borderRadius: 4, padding: '0.25rem 0.5rem', fontSize: '0.6875rem', fontWeight: 600, cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: '0.25rem'
                }}
              >
                <Layers size={12} /> By Category
              </button>
            </div>
          </div>

          {/* Chart Content Area */}
          <div style={{ flex: 1, minHeight: 250 }}>
            {chartTab === 'top10' && (
              <div>
                <p style={{ margin: '0 0 0.5rem', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                  Top 10 elevated threat scenarios: Comparing NIST Threat Likelihood vs Adverse Impact
                </p>
                <ResponsiveContainer width="100%" height={230}>
                  <BarChart data={top10Data} margin={{ top: 10, right: 10, left: -20, bottom: 25 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" />
                    <XAxis dataKey="name" angle={-25} textAnchor="end" interval={0} tick={{ fill: 'var(--color-text-muted)', fontSize: 9 }} />
                    <YAxis domain={[0, 10]} tick={{ fill: 'var(--color-text-muted)', fontSize: 10 }} />
                    <Tooltip contentStyle={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: '0.75rem', color: 'var(--color-text-primary)' }} />
                    <Legend wrapperStyle={{ fontSize: '0.6875rem', paddingTop: '4px' }} />
                    <Bar dataKey="Likelihood" fill="#f59e0b" radius={[3, 3, 0, 0]} name="Likelihood (0-10)" />
                    <Bar dataKey="Impact" fill="#ef4444" radius={[3, 3, 0, 0]} name="Impact (0-10)" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {chartTab === 'distribution' && (
              <div>
                <ResponsiveContainer width="100%" height={190}>
                  <PieChart>
                    <Pie data={distributionData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={48} outerRadius={78} paddingAngle={3}>
                      {distributionData.map((d, i) => <Cell key={i} fill={d.color} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: '0.75rem', color: 'var(--color-text-primary)' }} />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
                  {distributionData.map(d => (
                    <span
                      key={d.name}
                      onClick={() => setSelectedTier(selectedTier === d.tierKey ? 'ALL' : d.tierKey)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.6875rem',
                        color: selectedTier === d.tierKey ? 'var(--color-cyber-blue)' : 'var(--color-text-muted)',
                        cursor: 'pointer', padding: '0.125rem 0.375rem', borderRadius: 4,
                        background: selectedTier === d.tierKey ? 'rgba(0, 212, 255, 0.1)' : 'transparent'
                      }}
                    >
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: d.color, display: 'inline-block' }} />
                      {d.name}: {d.value}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {chartTab === 'categories' && (
              <div>
                <p style={{ margin: '0 0 0.5rem', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                  Average NIST composite risk score by intelligence category
                </p>
                <ResponsiveContainer width="100%" height={230}>
                  <BarChart data={categoryData} layout="vertical" margin={{ top: 5, right: 20, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" />
                    <XAxis type="number" domain={[0, 100]} tick={{ fill: 'var(--color-text-muted)', fontSize: 10 }} />
                    <YAxis dataKey="name" type="category" tick={{ fill: 'var(--color-text-secondary)', fontSize: 10 }} />
                    <Tooltip contentStyle={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: '0.75rem', color: 'var(--color-text-primary)' }} />
                    <Bar dataKey="avgScore" fill="#00d4ff" radius={[0, 4, 4, 0]} name="Avg NIST Risk Score" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Risk Findings Table Header & Filter Bar */}
      <div className="card" style={{ padding: 0, overflow: 'hidden', border: '1px solid var(--color-border)' }}>
        <div style={{
          padding: '1rem 1.25rem', borderBottom: '1px solid var(--color-border)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem'
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                NIST SP 800-30 Risk Findings
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', background: 'var(--color-bg-input)', padding: '0.125rem 0.5rem', borderRadius: 9999 }}>
                {filteredScores.length} of {enrichedScores.length}
              </span>
            </div>
            {matrixFilter && (
              <div style={{ marginTop: '0.25rem', fontSize: '0.6875rem', color: 'var(--color-cyber-blue)', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                <Filter size={11} /> Filtered by Matrix: Likelihood {TIER_LABELS[matrixFilter.lIndex]} × Impact {TIER_LABELS[matrixFilter.iIndex]}
                <button
                  onClick={() => setMatrixFilter(null)}
                  style={{ background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', textDecoration: 'underline', padding: 0 }}
                >
                  Clear
                </button>
              </div>
            )}
          </div>

          {/* Controls: Search & Tier Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            {/* Search */}
            <div style={{ position: 'relative', width: 200 }}>
              <Search size={13} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
              <input
                type="text"
                placeholder="Search findings..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  width: '100%', padding: '0.35rem 0.625rem 0.35rem 1.75rem',
                  fontSize: '0.75rem', background: 'var(--color-bg-input)',
                  border: '1px solid var(--color-border)', borderRadius: 6,
                  color: 'var(--color-text-primary)', outline: 'none'
                }}
              />
            </div>

            {/* Severity Tier Filter Chips */}
            <div style={{ display: 'flex', gap: '0.25rem' }}>
              {['ALL', 'Critical', 'High', 'Moderate', 'Low'].map(tier => {
                const isSelected = selectedTier.toUpperCase() === tier.toUpperCase();
                return (
                  <button
                    key={tier}
                    onClick={() => setSelectedTier(tier)}
                    style={{
                      background: isSelected ? 'var(--color-cyber-blue)' : 'var(--color-bg-input)',
                      color: isSelected ? '#000' : 'var(--color-text-muted)',
                      border: '1px solid var(--color-border)',
                      borderRadius: 4, padding: '0.25rem 0.5rem', fontSize: '0.6875rem', fontWeight: 600,
                      cursor: 'pointer', transition: 'all 0.15s ease'
                    }}
                  >
                    {tier}
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Findings Table */}
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'rgba(255, 255, 255, 0.02)' }}>
                <th style={{ textAlign: 'left', padding: '0.75rem 1rem' }}>Threat Finding</th>
                <th style={{ textAlign: 'left', padding: '0.75rem 0.75rem' }}>Evidence Preview</th>
                <th style={{ textAlign: 'center', padding: '0.75rem 0.5rem', minWidth: 105 }}>
                  Threat Likelihood
                  <span style={{ display: 'block', fontSize: '0.5625rem', color: 'var(--color-text-muted)', fontWeight: 400 }}>0–10 Scale</span>
                </th>
                <th style={{ textAlign: 'center', padding: '0.75rem 0.5rem', minWidth: 95 }}>
                  Adverse Impact
                  <span style={{ display: 'block', fontSize: '0.5625rem', color: 'var(--color-text-muted)', fontWeight: 400 }}>0–10 Scale</span>
                </th>
                <th style={{ textAlign: 'center', padding: '0.75rem 0.5rem', minWidth: 100 }}>
                  NIST Risk Score
                  <span style={{ display: 'block', fontSize: '0.5625rem', color: 'var(--color-text-muted)', fontWeight: 400 }}>L × I (0–100)</span>
                </th>
                <th style={{ textAlign: 'center', padding: '0.75rem 0.75rem' }}>NIST Risk Tier</th>
                <th style={{ width: 40, padding: '0.75rem 0.5rem' }}></th>
              </tr>
            </thead>
            <tbody>
              {filteredScores.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--color-text-muted)', fontSize: '0.8125rem' }}>
                    No findings match the selected NIST risk filters.
                  </td>
                </tr>
              ) : (
                filteredScores.map(rs => {
                  const isExpanded = selected === rs.id;
                  const tierColor = TIER_COLORS[rs.nistTier] || '#64748b';

                  return (
                    <tr
                      key={rs.id}
                      onClick={() => setSelected(isExpanded ? null : rs.id)}
                      style={{
                        cursor: 'pointer',
                        background: isExpanded ? 'rgba(0, 212, 255, 0.04)' : undefined,
                        borderLeft: isExpanded ? '3px solid var(--color-cyber-blue)' : '3px solid transparent',
                        transition: 'background 0.15s ease'
                      }}
                    >
                      <td style={{ padding: '0.75rem 1rem', maxWidth: 240 }}>
                        <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--color-text-primary)', marginBottom: '0.125rem' }}>
                          {rs.finding?.title || 'Finding'}
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                          <span style={{
                            fontSize: '0.625rem', padding: '0.05rem 0.35rem', borderRadius: 3,
                            background: 'var(--color-bg-input)', color: 'var(--color-cyber-blue)', textTransform: 'uppercase'
                          }}>
                            {rs.finding?.category || rs.finding?.finding_type || 'finding'}
                          </span>
                          {rs.finding?.source && (
                            <span style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)' }}>
                              via {rs.finding.source}
                            </span>
                          )}
                        </div>
                      </td>

                      <td style={{ padding: '0.75rem 0.75rem', fontSize: '0.75rem', color: 'var(--color-text-muted)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {rs.finding?.evidence || '—'}
                      </td>

                      {/* Threat Event Likelihood Bar */}
                      <td style={{ padding: '0.75rem 0.5rem', textAlign: 'center' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.25rem' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', fontWeight: 600, color: '#f59e0b' }}>
                            {rs.likelihood}
                          </span>
                          <div style={{ width: 60, height: 4, background: 'rgba(255, 255, 255, 0.08)', borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{ width: `${(rs.likelihood / 10) * 100}%`, height: '100%', background: '#f59e0b' }} />
                          </div>
                        </div>
                      </td>

                      {/* Adverse Impact Bar */}
                      <td style={{ padding: '0.75rem 0.5rem', textAlign: 'center' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.25rem' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', fontWeight: 600, color: '#ef4444' }}>
                            {rs.impact}
                          </span>
                          <div style={{ width: 60, height: 4, background: 'rgba(255, 255, 255, 0.08)', borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{ width: `${(rs.impact / 10) * 100}%`, height: '100%', background: '#ef4444' }} />
                          </div>
                        </div>
                      </td>

                      {/* Composite Score */}
                      <td style={{ padding: '0.75rem 0.5rem', textAlign: 'center' }}>
                        <span style={{
                          fontFamily: 'var(--font-mono)', fontSize: '1rem', fontWeight: 800,
                          color: tierColor
                        }}>
                          {rs.composite_score}
                        </span>
                      </td>

                      {/* Risk Tier Badge */}
                      <td style={{ padding: '0.75rem 0.75rem', textAlign: 'center' }}>
                        <span className={getRiskBg(rs.risk_level)} style={{
                          padding: '0.2rem 0.55rem', borderRadius: 9999,
                          fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.02em',
                          display: 'inline-block'
                        }}>
                          {rs.risk_level}
                        </span>
                      </td>

                      {/* Toggle Chevron */}
                      <td style={{ padding: '0.75rem 0.5rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                        {isExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Expanded NIST SP 800-30 Assessment Rationale Drawer */}
      {selected && enrichedScores.find(rs => rs.id === selected) && (
        (() => {
          const s = enrichedScores.find(rs => rs.id === selected);
          const tierColor = TIER_COLORS[s.nistTier] || '#64748b';
          return (
            <div className="card animate-slide-in" style={{
              marginTop: '1rem',
              background: 'linear-gradient(135deg, rgba(26, 31, 54, 0.98), rgba(17, 24, 39, 0.98))',
              border: `1px solid ${tierColor}55`,
              boxShadow: `0 8px 24px rgba(0, 0, 0, 0.4), 0 0 16px ${tierColor}15`
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.875rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <ShieldAlert size={16} color={tierColor} />
                    <h4 style={{ fontSize: '0.9375rem', fontWeight: 700, margin: 0, color: 'var(--color-text-primary)' }}>
                      NIST SP 800-30 Assessment: {s.finding?.title || 'Finding'}
                    </h4>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                    Finding ID: <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyber-blue)' }}>{s.finding_id}</code>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span className={getRiskBg(s.risk_level)} style={{ padding: '0.2rem 0.625rem', borderRadius: 9999, fontSize: '0.75rem', fontWeight: 700 }}>
                    {s.risk_level} RISK (Score: {s.composite_score})
                  </span>
                  <button
                    onClick={() => setSelected(null)}
                    style={{ background: 'transparent', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', fontSize: '0.75rem' }}
                  >
                    Close ×
                  </button>
                </div>
              </div>

              {/* Step-by-Step NIST Formula Breakdown */}
              <div style={{
                display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem',
                background: 'rgba(0, 0, 0, 0.25)', border: '1px solid var(--color-border)',
                borderRadius: 8, padding: '0.875rem', marginBottom: '1rem'
              }}>
                <div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                    1. Exposure Level (E)
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-cyber-blue)' }}>
                    {s.exposure} <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>/ 10</span>
                  </div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>Public visibility on OSINT</div>
                </div>

                <div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                    2. Exploitability (Ex)
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#f59e0b' }}>
                    {s.exploitability} <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>/ 10</span>
                  </div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>Ease of weaponization</div>
                </div>

                <div>
                  <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                    3. Confidence Factor (C)
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#a855f7' }}>
                    {s.confidence > 1 ? s.confidence : Math.round(s.confidence * 100)}%
                  </div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>OSINT corroboration</div>
                </div>

                <div style={{ borderLeft: '1px solid rgba(255, 255, 255, 0.1)', paddingLeft: '0.75rem' }}>
                  <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                    Threat Likelihood (L)
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#f59e0b' }}>
                    {s.likelihood} <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>/ 10</span>
                  </div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>Avg(E, Ex) × Conf</div>
                </div>

                <div style={{ borderLeft: '1px solid rgba(255, 255, 255, 0.1)', paddingLeft: '0.75rem' }}>
                  <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                    Adverse Impact (I)
                  </div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#ef4444' }}>
                    {s.impact} <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>/ 10</span>
                  </div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>Asset &amp; business impact</div>
                </div>
              </div>

              {/* Rationale and Evidence */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
                <div>
                  <h5 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-secondary)', margin: '0 0 0.375rem', textTransform: 'uppercase' }}>
                    Assessment Rationale
                  </h5>
                  <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-primary)', margin: 0, lineHeight: 1.6, background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: 6, border: '1px solid var(--color-border)' }}>
                    {s.rationale || 'Risk assessed according to NIST SP 800-30 Rev. 1 criteria.'}
                  </p>
                </div>

                <div>
                  <h5 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-secondary)', margin: '0 0 0.375rem', textTransform: 'uppercase' }}>
                    Corroborating Evidence
                  </h5>
                  <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)', background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: 6, border: '1px solid var(--color-border)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {s.finding?.evidence || s.finding?.description || 'No direct raw evidence payload.'}
                  </div>
                </div>
              </div>
            </div>
          );
        })()
      )}

      {/* NIST SP 800-30 Rev. 1 Official Reference Card */}
      <div style={{
        marginTop: '1.5rem', padding: '1rem 1.25rem',
        background: 'rgba(0, 212, 255, 0.03)', border: '1px solid rgba(0, 212, 255, 0.18)',
        borderRadius: 8, fontSize: '0.75rem', color: 'var(--color-text-muted)', lineHeight: 1.6
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem', color: 'var(--color-cyber-blue)', fontWeight: 600 }}>
          <Info size={15} />
          <span>NIST SP 800-30 Rev. 1 Standard Specification</span>
        </div>
        <div>
          Risk scoring methodology follows <strong>NIST Special Publication 800-30 Revision 1</strong> (<em>Guide for Conducting Risk Assessments</em>). Risk is quantified as the product of <strong>Threat Event Likelihood</strong> (incorporating threat source exposure, vulnerability exploitability, and OSINT evidence confidence) and <strong>Adverse Impact</strong> (evaluating harm to organizational assets, operations, and confidentiality). Standard semi-quantitative tiers: <strong>Very High</strong> (80.1–100), <strong>High</strong> (60.1–80), <strong>Moderate</strong> (40.1–60), <strong>Low</strong> (20.1–40), and <strong>Very Low</strong> (0–20).
        </div>
      </div>
    </div>
  );
}
