import { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Key, Database, Shield, ToggleLeft, ToggleRight } from 'lucide-react';
import { getSettings } from '../services/api';

export default function Settings() {
  const [settings, setSettings] = useState(null);
  const [mode, setMode] = useState('demo');

  useEffect(() => {
    getSettings().then(s => {
      setSettings(s);
      setMode(s.mode || 'demo');
    }).catch(() => {});
  }, []);

  const apiKeys = [
    { key: 'github_configured',        label: 'GitHub Token',           desc: 'Public repository and code search, email extraction from commits' },
    { key: 'shodan_configured',         label: 'Shodan API Key',          desc: 'Passive infrastructure and open-port data for IP targets' },
    { key: 'virustotal_configured',     label: 'VirusTotal API Key',      desc: 'Threat intelligence, domain reputation, and certificate lookups' },
    { key: 'censys_configured',         label: 'Censys API Key',          desc: 'Certificate and host search for infrastructure mapping' },
    { key: 'hunter_configured',         label: 'Hunter.io API Key',       desc: 'Email address discovery for target domain (25 req/month free)' },
    { key: 'hibp_configured',           label: 'Have I Been Pwned Key',   desc: 'Breach database lookup for domain email addresses (paid API)' },
    { key: 'emailrep_configured',       label: 'EmailRep API Key',        desc: 'Email reputation and risk scoring (100 req/day free)' },
    { key: 'securitytrails_configured', label: 'SecurityTrails API Key',  desc: 'Passive DNS, subdomain enumeration, and historical records' },
    { key: 'firebase_configured',       label: 'Firebase Project ID',     desc: 'Optional cloud sync layer for scan persistence across sessions' },
  ];

  return (
    <div className="animate-fade-in" style={{ maxWidth: 800 }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0 }}>Settings</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          Configure application mode and API integrations.
        </p>
      </div>

      {/* Mode */}
      <div className="card" style={{ marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <Database size={16} color="var(--color-cyber-blue)" />
          <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 600 }}>Application Mode</h3>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div
            onClick={() => setMode('demo')}
            style={{
              padding: '1rem', borderRadius: 8, cursor: 'pointer',
              border: mode === 'demo' ? '2px solid var(--color-cyber-green)' : '1px solid var(--color-border)',
              background: mode === 'demo' ? 'rgba(34, 197, 94, 0.06)' : 'var(--color-bg-secondary)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem' }}>
              <ToggleLeft size={16} color={mode === 'demo' ? 'var(--color-cyber-green)' : 'var(--color-text-muted)'} />
              <span style={{ fontWeight: 600, color: mode === 'demo' ? 'var(--color-cyber-green)' : 'var(--color-text-muted)' }}>Demo Mode</span>
            </div>
            <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text-muted)', lineHeight: 1.5 }}>
              Uses the built-in ApexNova Technologies demo dataset. No API keys required. Perfect for demonstrations and academic presentations.
            </p>
          </div>
          <div
            onClick={() => setMode('live')}
            style={{
              padding: '1rem', borderRadius: 8, cursor: 'pointer',
              border: mode === 'live' ? '2px solid var(--color-cyber-blue)' : '1px solid var(--color-border)',
              background: mode === 'live' ? 'rgba(0, 212, 255, 0.06)' : 'var(--color-bg-secondary)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem' }}>
              <ToggleRight size={16} color={mode === 'live' ? 'var(--color-cyber-blue)' : 'var(--color-text-muted)'} />
              <span style={{ fontWeight: 600, color: mode === 'live' ? 'var(--color-cyber-blue)' : 'var(--color-text-muted)' }}>Live OSINT Mode</span>
            </div>
            <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text-muted)', lineHeight: 1.5 }}>
              Uses real passive OSINT APIs. Requires API keys to be configured. Only use against authorized targets.
            </p>
          </div>
        </div>
      </div>

      {/* API Keys */}
      <div className="card" style={{ marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
          <Key size={16} color="var(--color-cyber-orange)" />
          <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 600 }}>API Configuration</h3>
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: '1rem' }}>
          API keys are configured via the .env file in the backend directory. Status shown below:
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {apiKeys.map(api => (
            <div key={api.key} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '0.75rem', background: 'var(--color-bg-secondary)', borderRadius: 8,
            }}>
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>{api.label}</div>
                <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>{api.desc}</div>
              </div>
              <span style={{
                fontSize: '0.6875rem', padding: '0.125rem 0.5rem', borderRadius: 9999, fontWeight: 600,
                background: settings?.[api.key] ? 'rgba(34, 197, 94, 0.1)' : 'rgba(100, 116, 139, 0.1)',
                color: settings?.[api.key] ? '#22c55e' : 'var(--color-text-muted)',
              }}>
                {settings?.[api.key] ? 'Configured' : 'Not Configured'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Security */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <Shield size={16} color="var(--color-cyber-red)" />
          <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 600 }}>Security & Ethical Safeguards</h3>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
          {[
            'Passive reconnaissance by default',
            'No port scanning',
            'No brute force attacks',
            'No credential attacks',
            'No exploitation',
            'No authentication bypass',
            'No destructive actions',
            'No automated vulnerability exploitation',
            'No unnecessary personal data collection',
            'No illegal dark-web interaction',
            'Explicit authorization required for active validation',
            'Real data clearly distinguished from demo data',
          ].map((s, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
              <span style={{ color: 'var(--color-cyber-green)' }}>✓</span> {s}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
