import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Radar, Activity, Globe, Route, BarChart3,
  ShieldAlert, Shield, Clock, FileText, GraduationCap, Settings,
  Crosshair, Mail, User
} from 'lucide-react';

const navGroups = [
  {
    label: 'ANALYSIS',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/reconnaissance', icon: Radar, label: 'Reconnaissance' },
      { to: '/attack-surface', icon: Globe, label: 'Attack Surface' },
      { to: '/attack-paths', icon: Route, label: 'Attack Paths' },
      { to: '/risk-analysis', icon: BarChart3, label: 'Risk Analysis' },
    ],
  },
  {
    label: 'INTELLIGENCE',
    items: [
      { to: '/threat-intelligence', icon: ShieldAlert, label: 'Threat Intel' },
      { to: '/email-intelligence', icon: Mail, label: 'Email Intel' },
      { to: '/username-intel', icon: User, label: 'Username Intel' },
    ],
  },
  {
    label: 'PLATFORM',
    items: [
      { to: '/sources', icon: Activity, label: 'Source Health' },
      { to: '/defense', icon: Shield, label: 'Defense' },
      { to: '/timeline', icon: Clock, label: 'Timeline' },
      { to: '/reports', icon: FileText, label: 'Reports' },
      { to: '/research', icon: GraduationCap, label: 'Research' },
      { to: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
];

export default function Sidebar() {
  return (
    <aside
      style={{
        width: 240,
        minHeight: '100vh',
        background: 'var(--color-bg-sidebar)',
        borderRight: '1px solid var(--color-border)',
        display: 'flex',
        flexDirection: 'column',
        position: 'fixed',
        top: 0,
        left: 0,
        zIndex: 40,
      }}
    >
      {/* Logo */}
      <div style={{
        padding: '1.25rem 1rem',
        borderBottom: '1px solid var(--color-border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Crosshair size={24} color="var(--color-cyber-blue)" />
          <div>
            <div style={{
              fontSize: '0.875rem',
              fontWeight: 700,
              color: 'var(--color-cyber-blue)',
              letterSpacing: '0.05em',
            }}>
              OSINT-to-Attack-Path
            </div>
            <div style={{
              fontSize: '0.625rem',
              color: 'var(--color-text-muted)',
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
            }}>
              Passive Recon Framework
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '0.75rem 0.5rem', overflowY: 'auto' }}>
        {navGroups.map(group => (
          <div key={group.label} style={{ marginBottom: '0.5rem' }}>
            <div style={{ fontSize: '0.5625rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', padding: '0.5rem 0.75rem 0.25rem' }}>
              {group.label}
            </div>
            {group.items.map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                style={({ isActive }) => ({
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  padding: '0.625rem 0.75rem',
                  marginBottom: '0.125rem',
                  borderRadius: '8px',
                  fontSize: '0.8125rem',
                  fontWeight: isActive ? 600 : 400,
                  color: isActive ? 'var(--color-cyber-blue)' : 'var(--color-text-secondary)',
                  background: isActive ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
                  textDecoration: 'none',
                  transition: 'all 0.15s ease',
                })}
              >
                <Icon size={16} />
                {label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Footer disclaimer */}
      <div style={{
        padding: '0.75rem',
        borderTop: '1px solid var(--color-border)',
        fontSize: '0.625rem',
        color: 'var(--color-text-muted)',
        lineHeight: 1.4,
      }}>
        Authorized security research & academic use only.
      </div>
    </aside>
  );
}
