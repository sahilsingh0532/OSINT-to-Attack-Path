import { useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import {
  Globe, Layers, Shield, Lock, Cpu, GitBranch, Building2, AlertTriangle,
  Target, Route, Activity
} from 'lucide-react';
import useScanStore from '../stores/scanStore';
import { getRiskColor, getRiskBg } from '../utils/helpers';

const statCards = [
  { key: 'domains', label: 'Domains', icon: Globe, color: '#00d4ff' },
  { key: 'subdomains', label: 'Subdomains', icon: Layers, color: '#38bdf8' },
  { key: 'certificates', label: 'Certificates', icon: Lock, color: '#f59e0b' },
  { key: 'ip_asn', label: 'IP / ASN', icon: Shield, color: '#14b8a6' },
  { key: 'technologies', label: 'Technologies', icon: Cpu, color: '#8b5cf6' },
  { key: 'repositories', label: 'Public Repos', icon: GitBranch, color: '#22c55e' },
  { key: 'org_references', label: 'Org References', icon: Building2, color: '#ec4899' },
  { key: 'threat_indicators', label: 'Threat Indicators', icon: AlertTriangle, color: '#dc2626' },
  { key: 'exposure_points', label: 'Exposure Points', icon: Target, color: '#ef4444' },
  { key: 'attack_paths', label: 'Attack Paths', icon: Route, color: '#ea580c' },
];

export default function Dashboard() {
  const { dashboardStats, currentScan, loadScans, findings } = useScanStore();

  useEffect(() => {
    loadScans();
  }, []);

  const stats = dashboardStats;
  const riskScore = stats?.overall_risk_score || 0;
  const riskLevel = stats?.overall_risk_level || 'N/A';

  // Chart data
  const pieData = stats ? [
    { name: 'Infrastructure', value: (stats.domains || 0) + (stats.subdomains || 0) + (stats.ip_asn || 0) + (stats.certificates || 0), color: '#00d4ff' },
    { name: 'Technology', value: stats.technologies || 0, color: '#8b5cf6' },
    { name: 'Code', value: stats.repositories || 0, color: '#22c55e' },
    { name: 'Threat', value: stats.threat_indicators || 0, color: '#dc2626' },
    { name: 'Identity', value: stats.org_references || 0, color: '#ec4899' },
  ].filter(d => d.value > 0) : [];

  const barData = stats ? statCards.map(s => ({
    name: s.label.length > 8 ? s.label.slice(0, 8) + '..' : s.label,
    value: stats[s.key] || 0,
    color: s.color,
  })).filter(d => d.value > 0) : [];

  // Recent findings
  const recent = findings.slice(-8).reverse();

  return (
    <div className="animate-fade-in">
      {/* Title */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0, color: 'var(--color-text-primary)' }}>
          Dashboard
        </h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          {currentScan
            ? `Target: ${currentScan.target_domain} · Mode: ${currentScan.mode} · Status: ${currentScan.status}`
            : 'Enter a target domain and start passive reconnaissance.'
          }
        </p>
      </div>

      {!stats ? (
        <div style={{
          textAlign: 'center',
          padding: '4rem 2rem',
          color: 'var(--color-text-muted)',
        }}>
          <Activity size={48} style={{ marginBottom: '1rem', opacity: 0.3 }} />
          <div style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>No scan data yet</div>
          <div style={{ fontSize: '0.875rem' }}>
            Enter a target domain above and click "Start Passive Reconnaissance" to begin.
          </div>
        </div>
      ) : (
        <>
          {/* Stats Grid + Risk Score */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr)) 220px', gap: '0.75rem', marginBottom: '1.5rem' }}>
            {statCards.map(({ key, label, icon: Icon, color }) => (
              <div key={key} className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Icon size={14} color={color} />
                  <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                    {label}
                  </span>
                </div>
                <div className="stat-number" style={{ color }}>{stats[key] || 0}</div>
              </div>
            ))}

            {/* Risk Score */}
            <div className="card" style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              background: `linear-gradient(135deg, rgba(${riskLevel === 'CRITICAL' || riskLevel === 'VERY HIGH' ? '239,68,68' : riskLevel === 'HIGH' ? '245,158,11' : '59,130,246'}, 0.08), var(--color-bg-card))`,
            }}>
              <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                OSINT Risk Score
              </span>
              <div style={{ fontSize: '2.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: getRiskColor(riskLevel) }}>
                {Math.round(riskScore)}
              </div>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>/ 100</span>
              <span className={getRiskBg(riskLevel)} style={{ padding: '0.25rem 0.75rem', borderRadius: '9999px', fontSize: '0.6875rem', fontWeight: 700 }}>
                {riskLevel}
              </span>
            </div>
          </div>

          {/* Charts Row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
            {/* Source Distribution */}
            <div className="card">
              <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, margin: '0 0 1rem', color: 'var(--color-text-secondary)' }}>
                OSINT Source Distribution
              </h3>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3}>
                    {pieData.map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: '0.75rem', color: 'var(--color-text-primary)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem', justifyContent: 'center' }}>
                {pieData.map(d => (
                  <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: d.color, display: 'inline-block' }} />
                    {d.name} ({d.value})
                  </div>
                ))}
              </div>
            </div>

            {/* Findings Bar Chart */}
            <div className="card">
              <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, margin: '0 0 1rem', color: 'var(--color-text-secondary)' }}>
                Findings by Category
              </h3>
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={barData} layout="vertical" margin={{ left: 60, right: 16, top: 0, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" tick={{ fill: 'var(--color-text-muted)', fontSize: 11 }} width={60} />
                  <Tooltip
                    contentStyle={{ background: 'var(--color-bg-card)', border: '1px solid var(--color-border)', borderRadius: 8, fontSize: '0.75rem', color: 'var(--color-text-primary)' }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {barData.map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recent Findings */}
          <div className="card">
            <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, margin: '0 0 1rem', color: 'var(--color-text-secondary)' }}>
              Recent Findings
            </h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Source</th>
                  <th>Confidence</th>
                  <th>Observation</th>
                </tr>
              </thead>
              <tbody>
                {recent.map(f => (
                  <tr key={f.id}>
                    <td>
                      <span style={{
                        fontSize: '0.6875rem',
                        padding: '0.125rem 0.5rem',
                        borderRadius: 9999,
                        background: 'rgba(0, 212, 255, 0.1)',
                        color: 'var(--color-cyber-blue)',
                        fontWeight: 500,
                      }}>
                        {f.finding_type}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>{f.value.length > 50 ? f.value.slice(0, 50) + '...' : f.value}</td>
                    <td style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem' }}>{f.source}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem' }}>{Math.round(f.confidence * 100)}%</td>
                    <td>
                      <span style={{
                        fontSize: '0.6875rem',
                        padding: '0.125rem 0.5rem',
                        borderRadius: 9999,
                        background: f.observation_type === 'observed' ? 'rgba(34, 197, 94, 0.1)' :
                                    f.observation_type === 'inferred' ? 'rgba(59, 130, 246, 0.1)' : 'rgba(245, 158, 11, 0.1)',
                        color: f.observation_type === 'observed' ? '#22c55e' :
                               f.observation_type === 'inferred' ? '#3b82f6' : '#f59e0b',
                        fontWeight: 500,
                      }}>
                        {f.observation_type}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {recent.length === 0 && (
              <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--color-text-muted)', fontSize: '0.875rem' }}>
                No findings yet.
              </div>
            )}
          </div>

          {/* Disclaimer */}
          <div style={{
            marginTop: '1rem',
            padding: '0.75rem 1rem',
            background: 'rgba(59, 130, 246, 0.06)',
            border: '1px solid rgba(59, 130, 246, 0.15)',
            borderRadius: 8,
            fontSize: '0.6875rem',
            color: 'var(--color-text-muted)',
          }}>
            This is an academic risk-prioritization model and is not CVSS. All risk scores are estimates based on passive OSINT analysis only.
          </div>
        </>
      )}
    </div>
  );
}
