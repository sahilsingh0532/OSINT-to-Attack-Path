import { useState, useEffect } from 'react';
import {
  Mail, Search, CheckCircle, AlertTriangle, Shield, Globe, GitBranch,
  ExternalLink, Download, FileSpreadsheet, User, Building, MapPin,
  Clock, Server, ShieldCheck, ShieldAlert, AlertCircle, RefreshCw, Layers, Sparkles,
  Link as LinkIcon, Database, Check, ChevronRight, Lock, Key, FileText,
  Target, ArrowRight, ShieldX, Terminal,
  Filter, CheckCircle2, XCircle, Info, Activity
} from 'lucide-react';
import useScanStore from '../stores/scanStore';
import { getEmails, lookupEmail, downloadEmailExcel } from '../services/api';
import { exportEmailIntelToExcel } from '../utils/excelExport';
import EvidenceModal from '../components/common/EvidenceModal';

function SourcePill({ source }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
      padding: '0.2rem 0.6rem', borderRadius: 9999, fontSize: '0.6875rem', fontWeight: 600,
      background: 'rgba(0, 212, 255, 0.08)', color: 'var(--color-cyber-blue)',
      border: '1px solid rgba(0, 212, 255, 0.2)', fontFamily: 'var(--font-mono)',
      textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>
      {source}
    </span>
  );
}

function RiskBadge({ label, isPositive = false, isNeutral = false }) {
  const bg = isPositive
    ? 'rgba(34, 197, 94, 0.12)'
    : isNeutral
    ? 'rgba(148, 163, 184, 0.12)'
    : 'rgba(239, 68, 68, 0.12)';
  const border = isPositive
    ? 'rgba(34, 197, 94, 0.3)'
    : isNeutral
    ? 'rgba(148, 163, 184, 0.3)'
    : 'rgba(239, 68, 68, 0.3)';
  const color = isPositive ? '#22c55e' : isNeutral ? '#94a3b8' : '#ef4444';

  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
      padding: '0.25rem 0.625rem', borderRadius: 6, fontSize: '0.75rem',
      fontWeight: 700, background: bg, border: `1px solid ${border}`, color,
    }}>
      {label}
    </span>
  );
}

export default function EmailIntelligence() {
  const { currentScan } = useScanStore();
  const activeScanId = currentScan?.id || null;

  // Tabs: 'search' (Live OSINT Investigator) or 'scan' (Discovered scan findings)
  const [activeTab, setActiveTab] = useState('search');

  // Search state
  const [targetEmail, setTargetEmail] = useState('');
  const [intelData, setIntelData] = useState(null);
  const [isSearching, setIsSearching] = useState(false);
  const [searchError, setSearchError] = useState(null);
  const [exporting, setExporting] = useState(false);

  // Scan emails state
  const [scanEmails, setScanEmails] = useState([]);
  const [loadingScanEmails, setLoadingScanEmails] = useState(false);
  const [scanEmailsLoaded, setScanEmailsLoaded] = useState(false);
  const [scanFilter, setScanFilter] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Active view tab inside result dossier
  const [dossierTab, setDossierTab] = useState('breaches');

  // Security Posture state
  const [postureSubTab, setPostureSubTab] = useState('overview'); // 'overview' | 'scenarios' | 'matrix'
  const [matrixFilter, setMatrixFilter] = useState('ALL');

  // Load scan emails if available
  useEffect(() => {
    if (activeScanId) {
      loadScanEmailsData();
    }
  }, [activeScanId]);

  const loadScanEmailsData = async () => {
    if (!activeScanId) return;
    setLoadingScanEmails(true);
    try {
      const data = await getEmails(activeScanId);
      setScanEmails(data || []);
      setScanEmailsLoaded(true);
    } catch {
      setScanEmails([]);
    }
    setLoadingScanEmails(false);
  };

  const handleSearch = async (emailToQuery) => {
    const query = (emailToQuery || targetEmail).trim();
    if (!query) return;
    setTargetEmail(query);
    setIsSearching(true);
    setSearchError(null);
    setActiveTab('search');

    try {
      const res = await lookupEmail(query);
      if (res.error && !res.sources_queried) {
        setSearchError(res.error);
        setIntelData(null);
      } else {
        setIntelData(res);
      }
    } catch (err) {
      setSearchError(err.response?.data?.detail || err.message || 'Failed to complete OSINT email lookup');
      setIntelData(null);
    }
    setIsSearching(false);
  };

  const handleExcelExport = async () => {
    if (!intelData) return;
    setExporting(true);
    try {
      // Try backend high-fidelity Excel export first
      try {
        const blob = await downloadEmailExcel(intelData.email, intelData);
        const url = window.URL.createObjectURL(new Blob([blob]));
        const link = document.createElement('a');
        link.href = url;
        const cleanName = (intelData.email || 'investigation').replace(/[^a-zA-Z0-9_.-]/g, '_');
        link.setAttribute('download', `Email_Intel_${cleanName}.xlsx`);
        document.body.appendChild(link);
        link.click();
        link.parentNode.removeChild(link);
        window.URL.revokeObjectURL(url);
      } catch (beErr) {
        // Fallback to client-side SheetJS export
        exportEmailIntelToExcel(intelData);
      }
    } catch (e) {
      console.error('Export error:', e);
    }
    setExporting(false);
  };

  const identity = intelData?.identity || {};
  const reputation = intelData?.reputation || {};
  const dnsData = intelData?.dns || {};
  const commits = intelData?.github_commits?.commits || [];
  const codeRefs = intelData?.github_code?.references || [];
  const gitUsers = intelData?.github_users?.users || [];
  const webpages = identity.public_webpages || intelData?.public_web_pages?.pages || [];
  const socials = identity.social_profiles || [];
  const xon = intelData?.xposedornot || {};
  const breaches = xon.breaches || intelData?.breaches || [];

  // Unified Security Posture data (from backend or computed client-side fallback)
  const posture = intelData?.security_posture || {};
  const postureData = !intelData ? {} : (posture.composite_score !== undefined ? posture : {
    composite_score: reputation.credentials_leaked || xon.breached ? 64.5 : 22.0,
    health_score: reputation.credentials_leaked || xon.breached ? 35.5 : 78.0,
    grade: reputation.credentials_leaked || xon.breached ? 'D' : 'B',
    risk_level: reputation.credentials_leaked || xon.breached ? 'ELEVATED RISK' : 'LOW RISK',
    badge_color: reputation.credentials_leaked || xon.breached ? '#ea580c' : '#38bdf8',
    verdict: reputation.credentials_leaked || xon.breached
      ? 'Elevated Exposure: Credential leaks detected and permissive email authentication configuration present risk of account takeover and domain spoofing.'
      : 'Secure Posture: No compromised credentials, active threat flags, or critical email authentication vulnerabilities detected for this address.',
    pillars: {
      credential_exposure: {
        name: 'Credential & Identity Exposure',
        score: reputation.credentials_leaked || xon.breached ? 80.0 : 5.0,
        status: reputation.credentials_leaked || xon.breached ? 'CRITICAL' : 'CLEAN',
        description: `${breaches.length} breach incident(s) detected.`,
        metrics: {
          breaches_count: breaches.length,
          pastes_count: xon.pastes_count || 0,
          credentials_leaked: Boolean(reputation.credentials_leaked),
          data_breach: Boolean(reputation.data_breach || breaches.length > 0),
          password_risk: breaches.some(b => String(b.password_risk).toLowerCase().includes('plain') || String(b.password_risk).toLowerCase().includes('easy')) ? 'Plaintext / Crackable' : 'None Recorded',
        }
      },
      spoofing_vulnerability: {
        name: 'Domain Spoofability & Email Auth',
        score: dnsData.spf_status?.includes('Strict') && dnsData.dmarc_policy?.includes('REJECT') ? 10.0 : 48.0,
        status: dnsData.spf_status?.includes('Strict') && dnsData.dmarc_policy?.includes('REJECT') ? 'PROTECTED' : 'VULNERABLE',
        description: `SPF: ${dnsData.spf_status || 'Not Found'}; DMARC: ${dnsData.dmarc_policy || 'Not Enforced'}.`,
        metrics: {
          spf_status: dnsData.spf_status || 'Not Configured',
          dmarc_policy: dnsData.dmarc_policy || 'Not Enforced',
          spoofable: Boolean(reputation.spoofable ?? true),
          mail_provider: dnsData.mail_provider || 'Standard Exchange',
        }
      },
      domain_authenticity: {
        name: 'Account & Domain Authenticity',
        score: reputation.disposable ? 70.0 : 12.0,
        status: reputation.disposable ? 'DISPOSABLE' : 'VERIFIED',
        description: reputation.disposable ? 'Disposable burner mailbox detected' : 'Legitimate verified domain and deliverable mailbox',
        metrics: {
          deliverable: reputation.deliverable ?? true,
          disposable: Boolean(reputation.disposable),
          free_provider: Boolean(reputation.free_provider),
        }
      },
      threat_intelligence: {
        name: 'Threat Intel & Blacklist Signals',
        score: reputation.suspicious ? 75.0 : 15.0,
        status: reputation.suspicious ? 'SUSPICIOUS' : 'HIGH TRUST',
        description: `Reputation: ${(reputation.reputation || 'NEUTRAL').toUpperCase()}`,
        metrics: {
          reputation: reputation.reputation || 'neutral',
          suspicious: Boolean(reputation.suspicious),
          spam: Boolean(reputation.spam),
          references: reputation.references || 0,
        }
      }
    },
    attack_scenarios: [
      {
        id: 'scenario_credential_stuffing',
        title: 'Credential Stuffing & Lateral SSO Account Takeover',
        mitre_technique: 'T1110.004',
        mitre_name: 'Credential Stuffing',
        probability: 'HIGH',
        impact: 'CRITICAL',
        description: 'Adversary weaponizes leaked passwords and hashes from public breach archives against corporate SSO portals, VPN endpoints, and developer repos.',
        attack_steps: [
          'OSINT Harvest: Scrape historical hashes and plaintext password dumps associated with email.',
          'Hash Cracking & Replay: Test passwords against enterprise single sign-on endpoints.',
          'MFA Bypass: Exploit legacy endpoints or absence of hardware tokens.',
          'Lateral Movement: Access internal codebases, production infrastructure, and secrets.'
        ],
        mitigation: 'Enforce hardware-backed FIDO2 / WebAuthn MFA and mandate immediate password rotation.'
      },
      {
        id: 'scenario_domain_spoofing',
        title: 'Domain Spoofing & Business Email Compromise (BEC)',
        mitre_technique: 'T1566.002',
        mitre_name: 'Email Impersonation',
        probability: 'HIGH',
        impact: 'HIGH',
        description: 'Permissive SPF and non-rejecting DMARC policies enable threat actors to send forged emails appearing to originate directly from this address.',
        attack_steps: [
          'DNS Reconnaissance: Discover SoftFail (~all) SPF policy and non-enforced DMARC.',
          'SMTP Forgery: Relay unauthorized mail with spoofed From headers.',
          'Inbox Delivery: Mail transfer agents accept forged emails into recipient inboxes.',
          'Social Engineering: Target financial and engineering staff with fraudulent requests.'
        ],
        mitigation: 'Publish strict DMARC policy (p=reject) and enforce SPF hard-fail (-all).'
      }
    ],
    defensive_playbook: [
      {
        priority: 'P1 - Critical',
        category: 'Credential Hygiene',
        title: 'Enforce Hardware MFA & Force Password Invalidation',
        description: 'Target email was identified in public breach archives. Invalidate existing session tokens and mandate FIDO2 hardware keys.',
        effort: 'LOW',
        remediation_cmd: 'Revoke active SSO sessions & trigger password reset in identity provider'
      },
      {
        priority: 'P1 - Critical',
        category: 'Email Authentication',
        title: 'Harden DMARC to Strict Reject (p=reject) & SPF (-all)',
        description: 'Prevent domain spoofing and executive impersonation by configuring strict DMARC rejection.',
        effort: 'LOW',
        remediation_cmd: `DNS TXT: _dmarc.${dnsData?.domain || intelData?.domain || 'domain.com'} -> "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${dnsData?.domain || intelData?.domain || 'domain.com'}"`
      },
      {
        priority: 'P2 - High',
        category: 'Source Code Security',
        title: 'Deploy Secret Scanning & Require Signed Commits',
        description: 'Ensure all GitHub repositories scan for exposed tokens and enforce GPG commit verification.',
        effort: 'MEDIUM',
        remediation_cmd: 'git config --global commit.gpgsign true; git config --global user.signingkey <KEY_ID>'
      }
    ],
    posture_matrix: [
      {
        category: 'Authentication',
        control: 'SPF HardFail Enforcement',
        value: dnsData.spf_status || 'SoftFail (~all)',
        status: dnsData.spf_status?.includes('Strict') ? 'PASS' : 'WARNING',
        detail: 'SoftFail allows unauthorized senders mail to reach spam or inbox folders.',
        recommendation: 'Update SPF TXT record to end with -all.'
      },
      {
        category: 'Authentication',
        control: 'DMARC Rejection Enforcement',
        value: dnsData.dmarc_policy || 'Not Enforced',
        status: dnsData.dmarc_policy?.includes('REJECT') ? 'PASS' : 'WARNING',
        detail: 'DMARC p=reject protects domain reputation by discarding unauthenticated mail.',
        recommendation: 'Set p=reject; sp=reject with RUA reporting.'
      },
      {
        category: 'Breach Exposure',
        control: 'Data Breach Record',
        value: breaches.length > 0 ? `${breaches.length} Breach(es)` : 'Clean',
        status: breaches.length > 0 ? 'FAIL' : 'PASS',
        detail: 'Exposures enable automated credential stuffing attacks.',
        recommendation: 'Enforce password complexity and MFA.'
      },
      {
        category: 'Breach Exposure',
        control: 'Credentials Leaked Flag',
        value: reputation.credentials_leaked ? 'Detected in Leaks' : 'None Detected',
        status: reputation.credentials_leaked ? 'FAIL' : 'PASS',
        detail: 'Passwords or authentication tokens discovered in past leaks.',
        recommendation: 'Immediate credential rotation.'
      },
      {
        category: 'Account Integrity',
        control: 'Mailbox Deliverability Verification',
        value: reputation.deliverable ? 'Deliverable' : 'Unknown / Undeliverable',
        status: reputation.deliverable ? 'PASS' : 'WARNING',
        detail: 'Active deliverability confirms real recipient presence.',
        recommendation: 'Verify MX routing configuration.'
      },
      {
        category: 'Account Integrity',
        control: 'Disposable / Burner Email Filter',
        value: reputation.disposable ? 'Disposable Address' : 'Legitimate Domain',
        status: reputation.disposable ? 'FAIL' : 'PASS',
        detail: 'Disposable mailboxes are frequently used for fraudulent signups.',
        recommendation: 'Block burner domains on corporate portals.'
      },
      {
        category: 'Threat Intelligence',
        control: 'EmailRep Threat Reputation',
        value: String(reputation.reputation || 'NEUTRAL').toUpperCase(),
        status: reputation.reputation === 'high' ? 'PASS' : reputation.suspicious ? 'FAIL' : 'NEUTRAL',
        detail: 'Aggregated sender trust and historical abuse reports.',
        recommendation: 'Monitor outbound mail flow.'
      },
      {
        category: 'Threat Intelligence',
        control: 'Suspicious Behavior Indicator',
        value: reputation.suspicious ? 'FLAGGED (Suspicious)' : 'Clean (No Flags)',
        status: reputation.suspicious ? 'FAIL' : 'PASS',
        detail: 'Observed in abuse feeds or malicious campaigns.',
        recommendation: 'Quarantine and audit identity logs.'
      }
    ]
  });

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', paddingBottom: '3rem' }} className="animate-fade-in">
      {/* ── Page Header ── */}
      <div style={{ marginBottom: '1.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
            <div style={{
              width: 44, height: 44, borderRadius: 12,
              background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(168, 85, 247, 0.2))',
              border: '1px solid rgba(0, 212, 255, 0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Mail size={22} color="var(--color-cyber-blue)" />
            </div>
            <div>
              <h1 style={{ margin: 0, fontSize: '1.625rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                Email Intelligence
              </h1>
              <p style={{ margin: '0.25rem 0 0', color: 'var(--color-text-muted)', fontSize: '0.8125rem' }}>
                Passive reconnaissance dossier using free OSINT tools (XposedOrNot Breach Intel, EmailRep, GitHub, Gravatar, DNS MX, Public Web Search)
              </p>
            </div>
          </div>

          {/* Navigation Mode Pill */}
          <div style={{
            display: 'flex', background: 'var(--color-bg-card)',
            padding: '0.25rem', borderRadius: 10, border: '1px solid var(--color-border)',
          }}>
            <button
              onClick={() => setActiveTab('search')}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem',
                padding: '0.5rem 1rem', borderRadius: 8, fontSize: '0.8125rem', fontWeight: 700,
                border: 'none', cursor: 'pointer',
                background: activeTab === 'search' ? 'var(--color-cyber-blue)' : 'transparent',
                color: activeTab === 'search' ? '#0a0e1a' : 'var(--color-text-secondary)',
                transition: 'all 0.15s ease',
              }}
            >
              <Search size={14} /> Live OSINT Search
            </button>
            <button
              onClick={() => setActiveTab('scan')}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem',
                padding: '0.5rem 1rem', borderRadius: 8, fontSize: '0.8125rem', fontWeight: 700,
                border: 'none', cursor: 'pointer',
                background: activeTab === 'scan' ? 'var(--color-cyber-blue)' : 'transparent',
                color: activeTab === 'scan' ? '#0a0e1a' : 'var(--color-text-secondary)',
                transition: 'all 0.15s ease',
              }}
            >
              <Layers size={14} /> Scan Database ({scanEmails.length})
            </button>
          </div>
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          TAB 1: LIVE OSINT EMAIL SEARCH
      ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'search' && (
        <div>
          {/* Search Box Card */}
          <div className="card" style={{ padding: '1.25rem', marginBottom: '1.5rem', position: 'relative' }}>
            <form
              onSubmit={(e) => { e.preventDefault(); handleSearch(); }}
              style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}
            >
              <div style={{
                flex: 1, minWidth: 260, display: 'flex', alignItems: 'center', gap: '0.75rem',
                background: 'var(--color-bg-input)', border: '1px solid var(--color-border)',
                borderRadius: 10, padding: '0.625rem 1rem',
              }}>
                <Search size={18} color="var(--color-cyber-blue)" />
                <input
                  type="email"
                  value={targetEmail}
                  onChange={(e) => setTargetEmail(e.target.value)}
                  placeholder="Enter target email (e.g. marcus.vance@apexnova.example or user@target.org)..."
                  required
                  style={{
                    flex: 1, background: 'none', border: 'none', outline: 'none',
                    color: 'var(--color-text-primary)', fontSize: '0.9375rem', fontFamily: 'var(--font-mono)',
                  }}
                />
                {targetEmail && (
                  <button
                    type="button"
                    onClick={() => setTargetEmail('')}
                    style={{ background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer' }}
                  >
                    ×
                  </button>
                )}
              </div>

              <button
                type="submit"
                disabled={isSearching || !targetEmail.trim()}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
                  padding: '0.6875rem 1.5rem', borderRadius: 10, border: 'none',
                  background: isSearching ? 'rgba(0, 212, 255, 0.4)' : 'var(--color-cyber-blue)',
                  color: '#0a0e1a', fontWeight: 700, fontSize: '0.875rem',
                  cursor: isSearching || !targetEmail.trim() ? 'not-allowed' : 'pointer',
                  boxShadow: '0 0 15px rgba(0, 212, 255, 0.25)',
                }}
              >
                {isSearching ? (
                  <>
                    <RefreshCw size={15} style={{ animation: 'spin 1s linear infinite' }} />
                    Investigating OSINT...
                  </>
                ) : (
                  <>
                    <Sparkles size={15} />
                    Search OSINT
                  </>
                )}
              </button>
            </form>

            {/* Quick Sample Targets */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.875rem', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontWeight: 600 }}>Quick Examples:</span>
              {[
                { label: 'Demo Staging Lead', email: 'marcus.vance@apexnova.example' },
                { label: 'Demo VP Engineering', email: 'elena.rostova@apexnova.example' },
                { label: 'Linus Torvalds', email: 'torvalds@linux-foundation.org' },
              ].map(ex => (
                <button
                  key={ex.email}
                  type="button"
                  onClick={() => handleSearch(ex.email)}
                  style={{
                    background: 'rgba(255, 255, 255, 0.04)', border: '1px solid var(--color-border)',
                    borderRadius: 6, padding: '0.2rem 0.5rem', fontSize: '0.6875rem',
                    color: 'var(--color-text-secondary)', cursor: 'pointer', fontFamily: 'var(--font-mono)',
                  }}
                >
                  {ex.label} <span style={{ color: 'var(--color-cyber-blue)' }}>({ex.email.split('@')[0]})</span>
                </button>
              ))}

              {/* Show scan email quick links if any exist */}
              {scanEmails.slice(0, 2).map(se => (
                <button
                  key={se.id}
                  type="button"
                  onClick={() => handleSearch(se.value)}
                  style={{
                    background: 'rgba(0, 212, 255, 0.08)', border: '1px solid rgba(0, 212, 255, 0.2)',
                    borderRadius: 6, padding: '0.2rem 0.5rem', fontSize: '0.6875rem',
                    color: 'var(--color-cyber-blue)', cursor: 'pointer', fontFamily: 'var(--font-mono)',
                  }}
                >
                  Scan: {se.value}
                </button>
              ))}
            </div>
          </div>

          {/* Search Error Alert */}
          {searchError && (
            <div style={{
              padding: '1rem', borderRadius: 10, marginBottom: '1.5rem',
              background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)',
              display: 'flex', alignItems: 'center', gap: '0.75rem', color: '#ef4444',
            }}>
              <AlertTriangle size={18} />
              <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>{searchError}</div>
            </div>
          )}

          {/* Loading Indicator */}
          {isSearching && (
            <div style={{ textAlign: 'center', padding: '4rem 1rem' }}>
              <div style={{
                width: 50, height: 50, borderRadius: '50%',
                border: '3px solid rgba(0, 212, 255, 0.2)', borderTopColor: 'var(--color-cyber-blue)',
                animation: 'spin 0.8s linear infinite', margin: '0 auto 1.25rem',
              }} />
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, margin: '0 0 0.5rem' }}>
                Querying Free OSINT Engines...
              </h3>
              <p style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', margin: 0, maxWidth: 450, marginInline: 'auto' }}>
                Interrogating EmailRep.io reputation, GitHub commits, GitHub public code, Gravatar profile hash, DNS MX infrastructure, and public search engine indexes.
              </p>
            </div>
          )}

          {/* Empty State before search */}
          {!intelData && !isSearching && !searchError && (
            <div className="card" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
              <Mail size={48} color="var(--color-cyber-blue)" style={{ opacity: 0.4, marginBottom: '1rem' }} />
              <h3 style={{ margin: '0 0 0.5rem', fontSize: '1.125rem', fontWeight: 700 }}>
                No Email Investigated Yet
              </h3>
              <p style={{ margin: 0, color: 'var(--color-text-muted)', fontSize: '0.875rem', maxWidth: 480, marginInline: 'auto' }}>
                Enter an email address above or click one of the quick examples to extract identity, public webpages, code repositories, email deliverability, and export to Excel (.xlsx).
              </p>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════════════════
              FULL OSINT INTELLIGENCE DOSSIER (WHEN DATA LOADED)
          ══════════════════════════════════════════════════════════════════ */}
          {intelData && !isSearching && (
            <div className="animate-fade-in">
              {/* Dossier Control Header */}
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1.25rem',
                padding: '0.875rem 1.25rem', background: 'var(--color-bg-card)',
                borderRadius: 12, border: '1px solid var(--color-border)',
              }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700 }}>
                      Dossier:
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '1rem', fontWeight: 800, color: 'var(--color-cyber-blue)' }}>
                      {intelData.email}
                    </span>
                    {intelData.is_demo && (
                      <span style={{
                        padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.625rem',
                        background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', fontWeight: 700,
                      }}>
                        DEMO SIMULATION
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
                    Queried: {intelData.sources_queried?.length || 0} sources · Responded: {intelData.sources_successful?.length || 0} sources
                  </div>
                </div>

                {/* ── EXCEL EXPORT BUTTON ── */}
                <button
                  onClick={handleExcelExport}
                  disabled={exporting}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
                    padding: '0.625rem 1.25rem', borderRadius: 8, border: 'none',
                    background: 'linear-gradient(135deg, #10b981, #059669)',
                    color: '#ffffff', fontWeight: 700, fontSize: '0.8125rem',
                    cursor: exporting ? 'not-allowed' : 'pointer',
                    boxShadow: '0 0 12px rgba(16, 185, 129, 0.3)',
                    transition: 'all 0.15s ease',
                  }}
                  title="Download multi-sheet Excel spreadsheet (.xlsx)"
                >
                  <FileSpreadsheet size={16} />
                  {exporting ? 'Generating Excel...' : 'Download Excel Report (.xlsx)'}
                </button>
              </div>

              {/* ── IDENTITY CARD ── */}
              <div className="card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1.25rem' }}>
                  <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'flex-start' }}>
                    {/* Avatar */}
                    <div style={{
                      width: 64, height: 64, borderRadius: 16, overflow: 'hidden',
                      background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(168, 85, 247, 0.2))',
                      border: '2px solid rgba(0, 212, 255, 0.4)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                    }}>
                      {identity.avatar_url ? (
                        <img
                          src={identity.avatar_url}
                          alt="Avatar"
                          onError={(e) => { e.target.style.display = 'none'; }}
                          style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                        />
                      ) : (
                        <User size={30} color="var(--color-cyber-blue)" />
                      )}
                    </div>

                    {/* Name & Core Entities */}
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                        <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                          {identity.name || identity.username || 'Identified Email Asset'}
                        </h2>
                        {identity.username && (
                          <span style={{
                            padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.75rem',
                            background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc',
                            fontFamily: 'var(--font-mono)', fontWeight: 600,
                          }}>
                            @{identity.username}
                          </span>
                        )}
                        {dnsData.mail_provider && (
                          <span style={{
                            padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.6875rem',
                            background: 'rgba(0, 212, 255, 0.1)', color: 'var(--color-cyber-blue)',
                            fontWeight: 700, border: '1px solid rgba(0, 212, 255, 0.2)',
                          }}>
                            {dnsData.mail_provider}
                          </span>
                        )}
                      </div>

                      <div style={{ fontSize: '0.875rem', fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)', marginTop: '0.25rem' }}>
                        {intelData.email}
                      </div>

                      {identity.bio && (
                        <p style={{ margin: '0.5rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)', lineHeight: 1.5, maxWidth: 650 }}>
                          {identity.bio}
                        </p>
                      )}

                      {/* Location & Company */}
                      <div style={{ display: 'flex', gap: '1.25rem', marginTop: '0.75rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', flexWrap: 'wrap' }}>
                        {identity.company && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                            <Building size={14} color="var(--color-cyber-blue)" />
                            <span>{identity.company}</span>
                          </div>
                        )}
                        {identity.location && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                            <MapPin size={14} color="#f59e0b" />
                            <span>{identity.location}</span>
                          </div>
                        )}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                          <Globe size={14} color="#22c55e" />
                          <span>Domain: <strong>{intelData.domain}</strong></span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Status Badges */}
                  <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', gap: '0.5rem', alignItems: 'flex-end' }}>
                    <div>
                      <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: '0.2rem' }}>
                        Breach Status (XposedOrNot)
                      </div>
                      <div>
                        {xon.breached ? (
                          <RiskBadge label={`BREACHED (${breaches.length || xon.breach_count || 1})`} isPositive={false} />
                        ) : (
                          <RiskBadge label="NO BREACHES" isPositive={true} />
                        )}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: '0.2rem' }}>
                        Reputation & Threat Index
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                        <span style={{
                          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                          width: 24, height: 24, borderRadius: 6, fontSize: '0.8125rem', fontWeight: 800,
                          background: `${postureData.badge_color || '#38bdf8'}22`,
                          color: postureData.badge_color || '#38bdf8',
                          border: `1px solid ${postureData.badge_color || '#38bdf8'}55`,
                        }}>
                          {postureData.grade || 'C'}
                        </span>
                        {reputation.reputation === 'high' ? (
                          <RiskBadge label="HIGH REPUTATION" isPositive={true} />
                        ) : reputation.suspicious ? (
                          <RiskBadge label="SUSPICIOUS" isPositive={false} />
                        ) : (
                          <RiskBadge label={(reputation.reputation || 'NEUTRAL').toUpperCase()} isNeutral={true} />
                        )}
                        <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {postureData.composite_score}/100 Risk
                        </span>
                      </div>
                    </div>
                    {reputation.references !== undefined && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                        {reputation.references} public references
                      </div>
                    )}
                  </div>
                </div>

                {/* Social Profiles Row */}
                {socials.length > 0 && (
                  <div style={{
                    marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid var(--color-border)',
                    display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap',
                  }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontWeight: 600 }}>Associated Platforms:</span>
                    {socials.map((sp, idx) => (
                      <a
                        key={idx}
                        href={sp.url || '#'}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                          padding: '0.25rem 0.625rem', borderRadius: 9999, fontSize: '0.75rem', fontWeight: 600,
                          background: 'rgba(255, 255, 255, 0.04)', color: 'var(--color-text-primary)',
                          border: '1px solid var(--color-border)', textDecoration: 'none',
                          cursor: sp.url ? 'pointer' : 'default',
                        }}
                      >
                        {sp.platform}
                        {sp.username && <span style={{ color: 'var(--color-cyber-blue)', fontFamily: 'var(--font-mono)' }}>({sp.username})</span>}
                        {sp.url && <ExternalLink size={10} color="var(--color-text-muted)" />}
                      </a>
                    ))}
                  </div>
                )}
              </div>

              {/* ── DOSSIER NAVIGATION TABS ── */}
              <div style={{
                display: 'flex', gap: '0.5rem', marginBottom: '1.25rem',
                borderBottom: '1px solid var(--color-border)', paddingBottom: '0.5rem', flexWrap: 'wrap',
              }}>
                {[
                  { key: 'breaches', label: `Breaches & Leaks (${breaches.length})`, icon: ShieldAlert },
                  { key: 'webpages', label: `Public Webpages (${webpages.length})`, icon: Globe },
                  { key: 'github', label: `GitHub & Code (${commits.length + codeRefs.length})`, icon: GitBranch },
                  {
                    key: 'reputation',
                    label: 'Reputation & Security Posture',
                    icon: ShieldCheck,
                    badge: postureData.grade ? `Grade ${postureData.grade}` : null,
                    badgeColor: postureData.badge_color,
                  },
                  { key: 'mail_infra', label: 'Domain & Mail Infrastructure', icon: Server },
                ].map(t => {
                  const Icon = t.icon;
                  const isSelected = dossierTab === t.key;
                  return (
                    <button
                      key={t.key}
                      onClick={() => setDossierTab(t.key)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: '0.5rem',
                        padding: '0.625rem 1rem', borderRadius: 8, fontSize: '0.8125rem', fontWeight: 700,
                        border: 'none', cursor: 'pointer',
                        background: isSelected ? 'rgba(0, 212, 255, 0.15)' : 'transparent',
                        color: isSelected ? 'var(--color-cyber-blue)' : 'var(--color-text-secondary)',
                        borderBottom: isSelected ? '2px solid var(--color-cyber-blue)' : '2px solid transparent',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <Icon size={15} />
                      {t.label}
                      {t.badge && (
                        <span style={{
                          padding: '0.125rem 0.45rem', borderRadius: 9999, fontSize: '0.6875rem',
                          fontWeight: 800, background: `${t.badgeColor || '#00d4ff'}22`,
                          color: t.badgeColor || '#00d4ff', border: `1px solid ${t.badgeColor || '#00d4ff'}44`,
                        }}>
                          {t.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>

              {/* ──────────────── TAB CONTENT ──────────────── */}

              {/* 0. DATA BREACHES & EXPOSURES (XPOSEDORNOT) */}
              {dossierTab === 'breaches' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  {/* Top Breach Metrics Cards */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.875rem' }}>
                    <div className="card" style={{
                      padding: '1.125rem',
                      background: xon.breached ? 'rgba(239, 68, 68, 0.05)' : 'rgba(34, 197, 94, 0.05)',
                      border: xon.breached ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(34, 197, 94, 0.3)',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem' }}>
                        {xon.breached ? <ShieldAlert size={16} color="#ef4444" /> : <ShieldCheck size={16} color="#22c55e" />}
                        <span style={{ fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', color: xon.breached ? '#ef4444' : '#22c55e' }}>
                          Exposure Status
                        </span>
                      </div>
                      <div style={{ fontSize: '1.125rem', fontWeight: 800, color: xon.breached ? '#ef4444' : '#22c55e' }}>
                        {xon.breached ? `BREACH DETECTED` : `CLEAN (NO BREACHES)`}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
                        {xon.breached ? `${breaches.length || xon.breach_count || 1} confirmed database exposure(s)` : 'No exposures in 10B+ credentials'}
                      </div>
                    </div>

                    <div className="card" style={{ padding: '1.125rem' }}>
                      <div style={{ fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '0.375rem' }}>
                        Exposure Risk Score
                      </div>
                      <div style={{ fontSize: '1.125rem', fontWeight: 800, color: xon.risk_score >= 7 ? '#ef4444' : xon.risk_score >= 4 ? '#f59e0b' : '#22c55e' }}>
                        {xon.risk_score || (xon.breached ? '7.5' : '0.0')} / 10
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
                        {xon.risk_label || (xon.breached ? 'Elevated Risk' : 'Zero Exposure')}
                      </div>
                    </div>

                    <div className="card" style={{ padding: '1.125rem' }}>
                      <div style={{ fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '0.375rem' }}>
                        Password Leak Status
                      </div>
                      <div style={{
                        fontSize: '1.125rem', fontWeight: 800,
                        color: breaches.some(b => ['plaintext', 'easytocrack'].includes(String(b.password_risk).toLowerCase())) ? '#ef4444' : xon.breached ? '#f59e0b' : '#22c55e'
                      }}>
                        {breaches.some(b => String(b.password_risk).toLowerCase() === 'plaintext')
                          ? 'PLAINTEXT PASSWORDS'
                          : breaches.some(b => ['easytocrack', 'weak'].includes(String(b.password_risk).toLowerCase()))
                          ? 'CRACKABLE HASHES'
                          : xon.breached ? 'CREDENTIAL EXPOSURE' : 'NONE DETECTED'}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
                        {xon.breached ? 'Immediate password rotation advised' : 'Clean authentication profile'}
                      </div>
                    </div>

                    <div className="card" style={{ padding: '1.125rem' }}>
                      <div style={{ fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--color-text-muted)', marginBottom: '0.375rem' }}>
                        Public Pastes
                      </div>
                      <div style={{ fontSize: '1.125rem', fontWeight: 800, color: xon.pastes_count > 0 ? '#f59e0b' : 'var(--color-text-primary)' }}>
                        {xon.pastes_count || 0} Paste(s)
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
                        Exposures in public paste text dumps
                      </div>
                    </div>
                  </div>

                  {/* Summary of Exposed Data Categories */}
                  {xon.exposed_data_types && xon.exposed_data_types.length > 0 && (
                    <div className="card" style={{ padding: '1rem 1.25rem' }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: '0.625rem' }}>
                        Compromised Data Categories Across All Breaches:
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                        {xon.exposed_data_types.map((dt, idx) => (
                          <span
                            key={idx}
                            style={{
                              padding: '0.25rem 0.625rem', borderRadius: 6, fontSize: '0.75rem', fontWeight: 600,
                              background: dt.toLowerCase().includes('password')
                                ? 'rgba(239, 68, 68, 0.12)'
                                : dt.toLowerCase().includes('token') || dt.toLowerCase().includes('ip')
                                ? 'rgba(245, 158, 11, 0.12)'
                                : 'rgba(0, 212, 255, 0.08)',
                              color: dt.toLowerCase().includes('password')
                                ? '#ef4444'
                                : dt.toLowerCase().includes('token') || dt.toLowerCase().includes('ip')
                                ? '#f59e0b'
                                : 'var(--color-cyber-blue)',
                              border: `1px solid ${
                                dt.toLowerCase().includes('password')
                                  ? 'rgba(239, 68, 68, 0.25)'
                                  : dt.toLowerCase().includes('token') || dt.toLowerCase().includes('ip')
                                  ? 'rgba(245, 158, 11, 0.25)'
                                  : 'rgba(0, 212, 255, 0.2)'
                              }`,
                            }}
                          >
                            {dt}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* List of Breaches */}
                  {breaches.length === 0 ? (
                    <div className="card" style={{ textAlign: 'center', padding: '3.5rem 1.5rem' }}>
                      <div style={{
                        width: 56, height: 56, borderRadius: '50%',
                        background: 'rgba(34, 197, 94, 0.12)', border: '1px solid rgba(34, 197, 94, 0.3)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        margin: '0 auto 1rem',
                      }}>
                        <ShieldCheck size={28} color="#22c55e" />
                      </div>
                      <h3 style={{ margin: '0 0 0.5rem', fontSize: '1.125rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                        No Known Data Breaches Found
                      </h3>
                      <p style={{ margin: 0, color: 'var(--color-text-muted)', fontSize: '0.875rem', maxWidth: 520, marginInline: 'auto', lineHeight: 1.6 }}>
                        Email <strong>{intelData.email}</strong> was checked against XposedOrNot's catalog of over 10+ billion records and 350+ public and private breach events. No matching compromises or exposed credentials were detected.
                      </p>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 0.25rem' }}>
                        <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                          Identified Breach Incidents ({breaches.length})
                        </span>
                        <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                          Source: XposedOrNot Public Catalog
                        </span>
                      </div>

                      {breaches.map((b, idx) => {
                        const xData = Array.isArray(b.xposed_data) ? b.xposed_data : (b.xposed_data ? String(b.xposed_data).split(';') : []);
                        const pRisk = String(b.password_risk || 'unknown').toLowerCase();
                        return (
                          <div key={idx} className="card" style={{
                            padding: '1.25rem',
                            borderLeft: pRisk === 'plaintext'
                              ? '4px solid #ef4444'
                              : pRisk === 'easytocrack'
                              ? '4px solid #f59e0b'
                              : '4px solid var(--color-cyber-blue)',
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
                                {b.logo ? (
                                  <img
                                    src={b.logo}
                                    alt={b.breach}
                                    onError={(e) => { e.target.style.display = 'none'; }}
                                    style={{ width: 40, height: 40, borderRadius: 8, objectFit: 'contain', background: '#ffffff', padding: 3 }}
                                  />
                                ) : (
                                  <div style={{
                                    width: 40, height: 40, borderRadius: 8,
                                    background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                  }}>
                                    <ShieldAlert size={20} color="#ef4444" />
                                  </div>
                                )}

                                <div>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                                    <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                                      {b.breach}
                                    </h3>
                                    {b.domain && (
                                      <span style={{
                                        fontFamily: 'var(--font-mono)', fontSize: '0.6875rem',
                                        color: 'var(--color-text-muted)', background: 'var(--color-bg-input)',
                                        padding: '0.125rem 0.375rem', borderRadius: 4,
                                      }}>
                                        {b.domain}
                                      </span>
                                    )}
                                    {b.industry && (
                                      <span style={{
                                        fontSize: '0.6875rem', color: 'var(--color-cyber-blue)',
                                        background: 'rgba(0, 212, 255, 0.08)', padding: '0.125rem 0.5rem', borderRadius: 9999,
                                        fontWeight: 600,
                                      }}>
                                        {b.industry}
                                      </span>
                                    )}
                                    {b.xposed_date && (
                                      <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                                        Year: {b.xposed_date}
                                      </span>
                                    )}
                                  </div>

                                  {b.xposed_records > 0 && (
                                    <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.25rem' }}>
                                      Affects: <strong style={{ color: 'var(--color-text-primary)' }}>{b.xposed_records.toLocaleString()}</strong> exposed accounts
                                    </div>
                                  )}
                                </div>
                              </div>

                              {/* Password Risk Badge */}
                              <div>
                                {pRisk === 'plaintext' ? (
                                  <RiskBadge label="PLAINTEXT PASSWORDS" isPositive={false} />
                                ) : pRisk === 'easytocrack' ? (
                                  <span style={{
                                    display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
                                    padding: '0.25rem 0.625rem', borderRadius: 6, fontSize: '0.75rem',
                                    fontWeight: 700, background: 'rgba(245, 158, 11, 0.12)', border: '1px solid rgba(245, 158, 11, 0.3)', color: '#f59e0b',
                                  }}>
                                    CRACKABLE HASHES
                                  </span>
                                ) : (
                                  <span style={{
                                    display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
                                    padding: '0.25rem 0.625rem', borderRadius: 6, fontSize: '0.75rem',
                                    fontWeight: 700, background: 'rgba(148, 163, 184, 0.12)', border: '1px solid rgba(148, 163, 184, 0.3)', color: '#94a3b8',
                                  }}>
                                    EXPOSURE RECORD
                                  </span>
                                )}
                              </div>
                            </div>

                            {/* Details description */}
                            {b.details && (
                              <p style={{
                                margin: '0.875rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-secondary)',
                                lineHeight: 1.6, background: 'rgba(0, 0, 0, 0.2)', padding: '0.75rem',
                                borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.03)',
                              }}>
                                {b.details}
                              </p>
                            )}

                            {/* Compromised data pills */}
                            {xData.length > 0 && (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', marginTop: '0.875rem', flexWrap: 'wrap' }}>
                                <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', fontWeight: 600 }}>Exposed:</span>
                                {xData.map((d, dIdx) => (
                                  <span
                                    key={dIdx}
                                    style={{
                                      padding: '0.125rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem',
                                      background: d.toLowerCase().includes('password') ? 'rgba(239, 68, 68, 0.12)' : 'rgba(255, 255, 255, 0.04)',
                                      color: d.toLowerCase().includes('password') ? '#ef4444' : 'var(--color-text-secondary)',
                                      border: `1px solid ${d.toLowerCase().includes('password') ? 'rgba(239, 68, 68, 0.3)' : 'var(--color-border)'}`,
                                      fontWeight: 600,
                                    }}
                                  >
                                    {d.trim()}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* 1. PUBLIC WEBPAGES */}
              {dossierTab === 'webpages' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {webpages.length === 0 ? (
                    <div className="card" style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--color-text-muted)' }}>
                      <Globe size={36} style={{ opacity: 0.3, marginBottom: '0.75rem' }} />
                      <div>No public webpages directly indexed for this email address.</div>
                    </div>
                  ) : (
                    webpages.map((p, i) => (
                      <div key={i} className="card" style={{ padding: '1.125rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem' }}>
                          <div>
                            <a
                              href={p.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{
                                color: 'var(--color-cyber-blue)', fontSize: '0.9375rem', fontWeight: 700,
                                textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                              }}
                            >
                              {p.title}
                              <ExternalLink size={13} />
                            </a>
                            <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)', wordBreak: 'break-all', marginTop: '0.2rem' }}>
                              {p.url}
                            </div>
                          </div>
                          <span style={{
                            padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.6875rem',
                            background: 'rgba(255, 255, 255, 0.04)', color: 'var(--color-text-muted)',
                            border: '1px solid var(--color-border)', flexShrink: 0,
                          }}>
                            {p.source || 'Web Search'}
                          </span>
                        </div>

                        {p.snippet && (
                          <div style={{
                            fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.5,
                            background: 'rgba(0, 0, 0, 0.2)', padding: '0.625rem 0.75rem', borderRadius: 6,
                            border: '1px solid rgba(255, 255, 255, 0.03)',
                          }}>
                            {p.snippet}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* 2. GITHUB COMMITS & CODE REFERENCES */}
              {dossierTab === 'github' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  {/* Commits Section */}
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                      <GitBranch size={16} color="var(--color-cyber-green)" />
                      <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 700 }}>
                        Public GitHub Commits by Author ({commits.length})
                      </h3>
                    </div>

                    {commits.length === 0 ? (
                      <div className="card" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '0.8125rem' }}>
                        No public commits authored by {intelData.email} found on GitHub.
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
                        {commits.map((c, i) => (
                          <div key={i} className="card" style={{ padding: '0.875rem 1.125rem' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
                              <div>
                                <a
                                  href={c.repo_url || `https://github.com/${c.repo}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  style={{
                                    fontSize: '0.875rem', fontWeight: 700, color: 'var(--color-cyber-blue)',
                                    fontFamily: 'var(--font-mono)', textDecoration: 'none',
                                    display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
                                  }}
                                >
                                  {c.repo} <ExternalLink size={11} />
                                </a>
                                <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-primary)', marginTop: '0.25rem', fontWeight: 500 }}>
                                  {c.message}
                                </div>
                              </div>
                              <div style={{ textAlign: 'right', flexShrink: 0 }}>
                                <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                                  {c.date ? new Date(c.date).toISOString().split('T')[0] : ''}
                                </span>
                                {c.commit_url && (
                                  <div>
                                    <a
                                      href={c.commit_url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      style={{ fontSize: '0.6875rem', color: 'var(--color-cyber-teal)', textDecoration: 'none' }}
                                    >
                                      View Commit →
                                    </a>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Code Search References */}
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                      <Search size={16} color="var(--color-cyber-purple)" />
                      <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 700 }}>
                        Code Files Referencing Email ({codeRefs.length})
                      </h3>
                    </div>

                    {codeRefs.length === 0 ? (
                      <div className="card" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '0.8125rem' }}>
                        No public repository code files referencing this email found.
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
                        {codeRefs.map((cd, i) => (
                          <div key={i} className="card" style={{ padding: '0.875rem 1.125rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div>
                              <div style={{ fontSize: '0.875rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>
                                {cd.file}
                              </div>
                              <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                                {cd.repo} / {cd.path}
                              </div>
                            </div>
                            {cd.file_url && (
                              <a
                                href={cd.file_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                style={{
                                  display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
                                  padding: '0.375rem 0.75rem', borderRadius: 6, fontSize: '0.75rem',
                                  background: 'rgba(168, 85, 247, 0.1)', color: '#c084fc',
                                  textDecoration: 'none', fontWeight: 600,
                                }}
                              >
                                View File <ExternalLink size={12} />
                              </a>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 3. REPUTATION & SECURITY POSTURE */}
              {dossierTab === 'reputation' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

                  {/* ── 1. HERO POSTURE SCOREBOARD BANNER ── */}
                  <div className="card" style={{
                    padding: '1.5rem',
                    background: 'linear-gradient(135deg, rgba(26, 31, 54, 0.95), rgba(17, 24, 39, 0.98))',
                    border: '1px solid var(--color-border)',
                    boxShadow: '0 8px 32px rgba(0, 0, 0, 0.36)',
                    position: 'relative', overflow: 'hidden',
                  }}>
                    {/* Glowing background accent */}
                    <div style={{
                      position: 'absolute', top: -50, right: -50, width: 200, height: 200,
                      background: `radial-gradient(circle, ${postureData.badge_color || '#00d4ff'}25 0%, transparent 70%)`,
                      pointerEvents: 'none',
                    }} />

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1.25rem' }}>
                      {/* Left: Grade Gauge & Resilience Score */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
                        <div style={{
                          width: 84, height: 84, borderRadius: 20,
                          background: `radial-gradient(circle at 30% 30%, ${postureData.badge_color || '#38bdf8'}22, rgba(15, 23, 42, 0.8))`,
                          border: `2px solid ${postureData.badge_color || '#38bdf8'}88`,
                          boxShadow: `0 0 24px ${postureData.badge_color || '#38bdf8'}33`,
                          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                          flexShrink: 0,
                        }}>
                          <span style={{ fontSize: '0.6875rem', fontWeight: 800, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                            GRADE
                          </span>
                          <span style={{ fontSize: '2.5rem', fontWeight: 900, lineHeight: 1, color: postureData.badge_color || '#38bdf8' }}>
                            {postureData.grade || 'C'}
                          </span>
                        </div>

                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <span style={{
                              display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
                              padding: '0.25rem 0.65rem', borderRadius: 9999, fontSize: '0.75rem', fontWeight: 800,
                              background: `${postureData.badge_color || '#38bdf8'}22`,
                              color: postureData.badge_color || '#38bdf8',
                              border: `1px solid ${postureData.badge_color || '#38bdf8'}55`,
                              letterSpacing: '0.03em',
                            }}>
                              <span style={{ width: 6, height: 6, borderRadius: '50%', background: postureData.badge_color || '#38bdf8', animation: 'pulse 2s infinite' }} />
                              {postureData.risk_level || 'EVALUATED POSTURE'}
                            </span>
                            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                              Target: {intelData?.email}
                            </span>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.75rem', flexWrap: 'wrap' }}>
                            <div style={{ fontSize: '1.75rem', fontWeight: 900, color: 'var(--color-text-primary)' }}>
                              {postureData.composite_score}
                              <span style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text-muted)' }}>/100</span>
                            </div>
                            <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--color-text-secondary)' }}>
                              NIST SP 800-30 Threat Index
                            </span>
                            <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>•</span>
                            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#38bdf8' }}>
                              Likelihood: {postureData.nist_assessment?.threat_likelihood ?? 'N/A'}/10
                            </span>
                            <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>•</span>
                            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#f59e0b' }}>
                              Impact: {postureData.nist_assessment?.threat_impact ?? 'N/A'}/10
                            </span>
                            <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>•</span>
                            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#22c55e' }}>
                              {postureData.health_score}% Resilience Health
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Verdict Quote Box */}
                    <div style={{
                      marginTop: '1.25rem', padding: '0.875rem 1rem', borderRadius: 8,
                      background: 'rgba(15, 23, 42, 0.65)', border: '1px solid rgba(255, 255, 255, 0.06)',
                      display: 'flex', alignItems: 'flex-start', gap: '0.75rem',
                    }}>
                      <ShieldAlert size={18} color={postureData.badge_color || 'var(--color-cyber-blue)'} style={{ flexShrink: 0, marginTop: 2 }} />
                      <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-primary)', lineHeight: 1.55 }}>
                        <strong style={{ color: postureData.badge_color || 'var(--color-cyber-blue)' }}>Security Operations Verdict: </strong>
                        {postureData.verdict}
                      </div>
                    </div>

                    {/* Quick Metric Chips Strip */}
                    <div style={{
                      marginTop: '1rem', paddingTop: '0.875rem', borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                      display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Lock size={14} color="#ef4444" />
                        <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Breaches:</span>
                        <strong style={{ fontSize: '0.75rem', color: breaches.length > 0 ? '#ef4444' : '#22c55e' }}>
                          {breaches.length > 0 ? `${breaches.length} Detected` : 'Clean (0)'}
                        </strong>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Shield size={14} color={dnsData.spf_status?.includes('Strict') ? '#22c55e' : '#f59e0b'} />
                        <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>SPF / DMARC:</span>
                        <strong style={{ fontSize: '0.75rem', color: dnsData.spf_status?.includes('Strict') ? '#22c55e' : '#f59e0b' }}>
                          {dnsData.spf_status?.includes('Strict') ? 'Strict Reject' : 'SoftFail / Permissive'}
                        </strong>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Mail size={14} color={reputation.deliverable ? '#22c55e' : '#94a3b8'} />
                        <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Deliverability:</span>
                        <strong style={{ fontSize: '0.75rem', color: reputation.deliverable ? '#22c55e' : '#94a3b8' }}>
                          {reputation.deliverable ? 'Deliverable' : 'Unknown'}
                        </strong>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Globe size={14} color={reputation.suspicious ? '#ef4444' : '#22c55e'} />
                        <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>EmailRep Trust:</span>
                        <strong style={{ fontSize: '0.75rem', color: reputation.suspicious ? '#ef4444' : '#22c55e' }}>
                          {String(reputation.reputation || 'NEUTRAL').toUpperCase()}
                        </strong>
                      </div>
                    </div>
                  </div>

                  {/* ── 2. SUB-NAVIGATION TABS (Segmented Control) ── */}
                  <div style={{
                    display: 'flex', gap: '0.375rem', background: 'var(--color-bg-secondary)',
                    padding: '0.375rem', borderRadius: 10, border: '1px solid var(--color-border)',
                    flexWrap: 'wrap',
                  }}>
                    {[
                      { id: 'overview', label: 'Executive Dashboard', icon: Activity },
                      {
                        id: 'scenarios',
                        label: `Attack Scenarios (${postureData.attack_scenarios?.length || 0})`,
                        icon: Target,
                      },
                      {
                        id: 'matrix',
                        label: `Controls Assessment (${postureData.posture_matrix?.length || 0})`,
                        icon: Layers,
                      },
                    ].map(sub => {
                      const SubIcon = sub.icon;
                      const active = postureSubTab === sub.id;
                      return (
                        <button
                          key={sub.id}
                          onClick={() => setPostureSubTab(sub.id)}
                          style={{
                            display: 'flex', alignItems: 'center', gap: '0.375rem',
                            padding: '0.5rem 0.875rem', borderRadius: 7, fontSize: '0.8125rem', fontWeight: 700,
                            border: 'none', cursor: 'pointer', transition: 'all 0.15s ease',
                            background: active ? 'rgba(0, 212, 255, 0.15)' : 'transparent',
                            color: active ? 'var(--color-cyber-blue)' : 'var(--color-text-muted)',
                            boxShadow: active ? '0 2px 8px rgba(0, 212, 255, 0.15)' : 'none',
                          }}
                        >
                          <SubIcon size={14} />
                          {sub.label}
                          {sub.badge && (
                            <span style={{
                              padding: '0.1rem 0.35rem', borderRadius: 9999, fontSize: '0.6875rem',
                              fontWeight: 800, background: '#22c55e22', color: '#22c55e', border: '1px solid #22c55e44',
                            }}>
                              {sub.badge}
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>

                  {/* ── 3. SUB-TAB VIEW: EXECUTIVE OVERVIEW ── */}
                  {postureSubTab === 'overview' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                      {/* 4 Pillars Grid */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
                        {Object.entries(postureData.pillars || {}).map(([key, pillar]) => {
                          const pScore = pillar.score || 0;
                          const pColor = pScore >= 75 ? '#ef4444' : pScore >= 50 ? '#ea580c' : pScore >= 25 ? '#f59e0b' : '#22c55e';
                          const IconComp = key === 'credential_exposure' ? Lock : key === 'spoofing_vulnerability' ? Shield : key === 'domain_authenticity' ? Globe : Activity;

                          return (
                            <div key={key} className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '0.875rem' }}>
                              <div>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                    <div style={{
                                      width: 28, height: 28, borderRadius: 6,
                                      background: `${pColor}22`, border: `1px solid ${pColor}44`,
                                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    }}>
                                      <IconComp size={14} color={pColor} />
                                    </div>
                                    <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                                      {pillar.name}
                                    </span>
                                  </div>
                                  <span style={{
                                    fontSize: '0.6875rem', fontWeight: 800, padding: '0.15rem 0.5rem',
                                    borderRadius: 4, background: `${pColor}18`, color: pColor, border: `1px solid ${pColor}44`,
                                  }}>
                                    {pillar.status}
                                  </span>
                                </div>

                                <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', lineHeight: 1.45, marginBottom: '0.75rem' }}>
                                  {pillar.description}
                                </div>
                              </div>

                              <div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6875rem', fontWeight: 700, color: 'var(--color-text-muted)', marginBottom: '0.35rem' }}>
                                  <span>RISK LEVEL</span>
                                  <span style={{ color: pColor, fontFamily: 'var(--font-mono)' }}>{pScore}/100</span>
                                </div>
                                <div style={{ width: '100%', height: 6, borderRadius: 9999, background: 'var(--color-bg-input)', overflow: 'hidden' }}>
                                  <div style={{ width: `${pScore}%`, height: '100%', borderRadius: 9999, background: pColor, transition: 'width 0.4s ease' }} />
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      {/* Top Attack Scenario Preview */}
                      {postureData.attack_scenarios?.[0] && (
                        <div className="card" style={{ padding: '1.25rem', borderLeft: '3px solid #ef4444' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                            <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 800, letterSpacing: '0.06em' }}>
                              Primary Exploitation Threat
                            </span>
                            <span style={{
                              fontSize: '0.6875rem', fontWeight: 800, padding: '0.15rem 0.5rem',
                              borderRadius: 4, background: 'rgba(239, 68, 68, 0.15)', color: '#ef4444',
                            }}>
                              {postureData.attack_scenarios[0].mitre_technique}
                            </span>
                          </div>

                          <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.9375rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                            {postureData.attack_scenarios[0].title}
                          </h4>
                          <p style={{ margin: '0 0 0.875rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                            {postureData.attack_scenarios[0].description}
                          </p>

                          <button
                            onClick={() => setPostureSubTab('scenarios')}
                            style={{
                              display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                              fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-cyber-blue)',
                              background: 'transparent', border: 'none', padding: 0, cursor: 'pointer',
                            }}
                          >
                            Explore Complete Attack Kill-Chain <ArrowRight size={12} />
                          </button>
                        </div>
                      )}

                      {/* Technical Attributes Matrix (Original 8 indicators + extra signals) */}
                      <div className="card" style={{ padding: '1.25rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                          <h4 style={{ margin: 0, fontSize: '0.875rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                            OSINT Signal Evaluation Matrix
                          </h4>
                          <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                            Synthesized from EmailRep.io, XposedOrNot & DNS MX records
                          </span>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '0.75rem' }}>
                          {[
                            {
                              label: 'Deliverability',
                              value: reputation.deliverable ? 'Deliverable Mailbox' : 'Unknown / Undeliverable',
                              isPos: Boolean(reputation.deliverable),
                            },
                            {
                              label: 'Suspicious Behavior',
                              value: reputation.suspicious ? 'Flagged as Suspicious' : 'Clean (No Threat Flags)',
                              isPos: !reputation.suspicious,
                            },
                            {
                              label: 'Credentials Leaked',
                              value: reputation.credentials_leaked ? 'Detected in Leaks' : 'None Detected',
                              isPos: !reputation.credentials_leaked,
                            },
                            {
                              label: 'Public Data Breaches',
                              value: breaches.length > 0 ? `${breaches.length} Breach Dumps` : 'None Detected',
                              isPos: breaches.length === 0,
                            },
                            {
                              label: 'Disposable Mailbox',
                              value: reputation.disposable ? 'Disposable Address' : 'Legitimate Corporate Domain',
                              isPos: !reputation.disposable,
                            },
                            {
                              label: 'Domain Spoofability',
                              value: dnsData.spf_status?.includes('Strict') && dnsData.dmarc_policy?.includes('REJECT') ? 'Protected (Strict)' : 'Permissive / Spoofable',
                              isPos: Boolean(dnsData.spf_status?.includes('Strict') && dnsData.dmarc_policy?.includes('REJECT')),
                            },
                            {
                              label: 'Mail Provider',
                              value: dnsData.mail_provider || 'Standard Mail Exchange',
                              isNeut: true,
                            },
                            {
                              label: 'First Seen In Feeds',
                              value: reputation.first_seen || 'Not Recorded',
                              isNeut: true,
                            },
                          ].map((item, idx) => (
                            <div key={idx} style={{
                              padding: '0.875rem', borderRadius: 8, background: 'var(--color-bg-secondary)',
                              border: '1px solid var(--color-border)', display: 'flex', flexDirection: 'column', gap: '0.25rem',
                            }}>
                              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                                {item.label}
                              </div>
                              <div style={{
                                fontSize: '0.8125rem', fontWeight: 700,
                                color: item.isPos ? '#22c55e' : item.isNeut ? 'var(--color-text-primary)' : '#ef4444',
                              }}>
                                {item.value}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* ── 4. SUB-TAB VIEW: ATTACK SCENARIOS ── */}
                  {postureSubTab === 'scenarios' && (
                    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      <div style={{
                        padding: '1rem', borderRadius: 8,
                        background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)',
                        fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.5,
                      }}>
                        <strong style={{ color: '#ef4444' }}>Threat Vector Modeling: </strong>
                        These realistic attack paths show how threat actors weaponize the discovered breaches, email spoofability gaps, and public developer profiles against {intelData?.email}.
                      </div>

                      {(postureData.attack_scenarios || []).map((sc, sIdx) => (
                        <div key={sIdx} className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                              <div style={{
                                width: 32, height: 32, borderRadius: 8,
                                background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                              }}>
                                <Target size={16} color="#ef4444" />
                              </div>
                              <div>
                                <h4 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                                  {sc.title}
                                </h4>
                                <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                                  MITRE ATT&CK: <strong style={{ color: 'var(--color-cyber-blue)' }}>{sc.mitre_technique}</strong> • {sc.mitre_name}
                                </div>
                              </div>
                            </div>

                            <div style={{ display: 'flex', gap: '0.375rem' }}>
                              <span style={{
                                padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 800,
                                background: sc.probability === 'HIGH' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                                color: sc.probability === 'HIGH' ? '#ef4444' : '#f59e0b',
                              }}>
                                Prob: {sc.probability}
                              </span>
                              <span style={{
                                padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 800,
                                background: sc.impact === 'CRITICAL' ? 'rgba(239, 68, 68, 0.25)' : 'rgba(245, 158, 11, 0.25)',
                                color: sc.impact === 'CRITICAL' ? '#ef4444' : '#f59e0b',
                              }}>
                                Impact: {sc.impact}
                              </span>
                            </div>
                          </div>

                          <p style={{ margin: 0, fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.55 }}>
                            {sc.description}
                          </p>

                          {/* Step-by-Step Kill Chain */}
                          <div>
                            <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 800, marginBottom: '0.5rem', letterSpacing: '0.06em' }}>
                              Attack Kill-Chain Stages
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                              {(sc.attack_steps || []).map((step, stepIdx) => (
                                <div key={stepIdx} style={{
                                  display: 'flex', alignItems: 'center', gap: '0.75rem',
                                  padding: '0.625rem 0.875rem', borderRadius: 6,
                                  background: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)',
                                }}>
                                  <div style={{
                                    width: 22, height: 22, borderRadius: '50%',
                                    background: 'rgba(0, 212, 255, 0.15)', color: 'var(--color-cyber-blue)',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    fontSize: '0.75rem', fontWeight: 800, flexShrink: 0,
                                  }}>
                                    {stepIdx + 1}
                                  </div>
                                  <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-primary)' }}>
                                    {step}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Mitigation Note */}
                          <div style={{
                            padding: '0.75rem 1rem', borderRadius: 6,
                            background: 'rgba(34, 197, 94, 0.08)', border: '1px solid rgba(34, 197, 94, 0.2)',
                            display: 'flex', alignItems: 'flex-start', gap: '0.5rem',
                          }}>
                            <ShieldCheck size={16} color="#22c55e" style={{ flexShrink: 0, marginTop: 1 }} />
                            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-primary)', lineHeight: 1.45 }}>
                              <strong style={{ color: '#22c55e' }}>Blue Team Defensive Mitigation: </strong>
                              {sc.mitigation}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}



                  {/* ── 6. SUB-TAB VIEW: CONTROLS MATRIX ── */}
                  {postureSubTab === 'matrix' && (
                    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      {/* Filter Pills */}
                      <div style={{ display: 'flex', gap: '0.375rem', flexWrap: 'wrap' }}>
                        {['ALL', 'Authentication', 'Breach Exposure', 'Domain Posture', 'Account Integrity', 'Threat Intelligence', 'OSINT Footprint'].map(cat => (
                          <button
                            key={cat}
                            onClick={() => setMatrixFilter(cat)}
                            style={{
                              padding: '0.35rem 0.75rem', borderRadius: 9999, fontSize: '0.75rem', fontWeight: 700,
                              border: 'none', cursor: 'pointer',
                              background: matrixFilter === cat ? 'var(--color-cyber-blue)' : 'var(--color-bg-secondary)',
                              color: matrixFilter === cat ? '#000' : 'var(--color-text-secondary)',
                            }}
                          >
                            {cat}
                          </button>
                        ))}
                      </div>

                      {/* Controls Assessment Table */}
                      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                        <div style={{ overflowX: 'auto' }}>
                          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
                            <thead>
                              <tr style={{ background: 'var(--color-bg-secondary)', borderBottom: '1px solid var(--color-border)' }}>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>Status</th>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>Control / Signal</th>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>Observed Finding</th>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>Technical Impact Detail</th>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>Hardening Guidance</th>
                              </tr>
                            </thead>
                            <tbody>
                              {(postureData.posture_matrix || [])
                                .filter(c => matrixFilter === 'ALL' || c.category === matrixFilter)
                                .map((c, mIdx) => {
                                  const isPass = c.status === 'PASS';
                                  const isFail = c.status === 'FAIL';
                                  const isWarn = c.status === 'WARNING';
                                  const statColor = isPass ? '#22c55e' : isFail ? '#ef4444' : isWarn ? '#f59e0b' : '#94a3b8';

                                  return (
                                    <tr key={mIdx} style={{ borderBottom: '1px solid var(--color-border)', transition: 'background 0.15s ease' }}>
                                      <td style={{ padding: '0.75rem 1rem', verticalAlign: 'top' }}>
                                        <span style={{
                                          display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
                                          padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 800,
                                          background: `${statColor}18`, color: statColor, border: `1px solid ${statColor}44`,
                                        }}>
                                          {isPass ? <CheckCircle size={10} /> : isFail ? <XCircle size={10} /> : <AlertTriangle size={10} />}
                                          {c.status}
                                        </span>
                                      </td>
                                      <td style={{ padding: '0.75rem 1rem', verticalAlign: 'top' }}>
                                        <div style={{ fontWeight: 700, color: 'var(--color-text-primary)' }}>{c.control}</div>
                                        <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>{c.category}</div>
                                      </td>
                                      <td style={{ padding: '0.75rem 1rem', verticalAlign: 'top', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--color-cyber-blue)' }}>
                                        {c.value}
                                      </td>
                                      <td style={{ padding: '0.75rem 1rem', verticalAlign: 'top', color: 'var(--color-text-secondary)', lineHeight: 1.45 }}>
                                        {c.detail}
                                      </td>
                                      <td style={{ padding: '0.75rem 1rem', verticalAlign: 'top', color: '#22c55e', fontSize: '0.75rem', lineHeight: 1.45 }}>
                                        {c.recommendation}
                                      </td>
                                    </tr>
                                  );
                                })}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  )}



                </div>
              )}

              {/* 4. DOMAIN & MAIL INFRASTRUCTURE */}
              {dossierTab === 'mail_infra' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div className="card" style={{ padding: '1.25rem' }}>
                    <h3 style={{ margin: '0 0 1rem', fontSize: '0.9375rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                      Mail Domain & Spoofing Protections: {dnsData.domain || intelData?.domain || 'Domain'}
                    </h3>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
                      <div style={{ padding: '0.875rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                          Identified Provider
                        </div>
                        <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--color-cyber-blue)', marginTop: '0.25rem' }}>
                          {dnsData.mail_provider || 'Standard Mail Exchange'}
                        </div>
                      </div>

                      <div style={{ padding: '0.875rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                          SPF Policy Status
                        </div>
                        <div style={{ fontSize: '1rem', fontWeight: 700, color: dnsData.spf_status?.includes('Strict') ? '#22c55e' : '#f59e0b', marginTop: '0.25rem' }}>
                          {dnsData.spf_status || 'Not Configured'}
                        </div>
                      </div>

                      <div style={{ padding: '0.875rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                          DMARC Policy Status
                        </div>
                        <div style={{ fontSize: '1rem', fontWeight: 700, color: dnsData.dmarc_policy?.includes('REJECT') ? '#22c55e' : '#f59e0b', marginTop: '0.25rem' }}>
                          {dnsData.dmarc_policy || 'Not Enforced'}
                        </div>
                      </div>
                    </div>

                    {/* Raw SPF and DMARC text records */}
                    {dnsData.spf_record && (
                      <div style={{ marginBottom: '0.75rem' }}>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', fontWeight: 600, marginBottom: '0.25rem' }}>
                          SPF TXT Record:
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', background: 'var(--color-bg-input)', padding: '0.5rem 0.75rem', borderRadius: 6, color: 'var(--color-text-secondary)' }}>
                          {dnsData.spf_record}
                        </div>
                      </div>
                    )}

                    {dnsData.dmarc_record && (
                      <div style={{ marginBottom: '1rem' }}>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', fontWeight: 600, marginBottom: '0.25rem' }}>
                          DMARC TXT Record:
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', background: 'var(--color-bg-input)', padding: '0.5rem 0.75rem', borderRadius: 6, color: 'var(--color-text-secondary)' }}>
                          {dnsData.dmarc_record}
                        </div>
                      </div>
                    )}

                    {/* MX Exchange Table */}
                    <div style={{ fontSize: '0.8125rem', fontWeight: 700, marginBottom: '0.5rem' }}>
                      Authoritative MX Exchange Servers:
                    </div>
                    {dnsData.mx_records?.length ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                        {dnsData.mx_records.map((mx, idx) => (
                          <div key={idx} style={{
                            display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0.75rem',
                            background: 'var(--color-bg-input)', borderRadius: 6, fontSize: '0.8125rem', fontFamily: 'var(--font-mono)',
                          }}>
                            <span style={{ color: 'var(--color-text-primary)' }}>{mx.exchange}</span>
                            <span style={{ color: 'var(--color-cyber-blue)', fontWeight: 700 }}>Priority: {mx.priority}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>No MX records found for this domain.</div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          TAB 2: SCAN DATABASE FINDINGS
      ══════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'scan' && (
        <div>
          {/* Header & Controls */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div>
              <h2 style={{ margin: 0, fontSize: '1.125rem', fontWeight: 700 }}>
                Emails Discovered During Domain Scans
              </h2>
              <p style={{ margin: '0.25rem 0 0', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                Target: {currentScan ? currentScan.target_domain : 'No scan active'}
              </p>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem',
                background: 'var(--color-bg-card)', border: '1px solid var(--color-border)',
                borderRadius: 8, padding: '0.375rem 0.75rem',
              }}>
                <Search size={14} color="var(--color-text-muted)" />
                <input
                  value={scanFilter}
                  onChange={(e) => setScanFilter(e.target.value)}
                  placeholder="Filter scan emails..."
                  style={{ background: 'none', border: 'none', outline: 'none', color: 'var(--color-text-primary)', fontSize: '0.8125rem', width: 160 }}
                />
              </div>

              <button
                onClick={loadScanEmailsData}
                disabled={!activeScanId || loadingScanEmails}
                style={{
                  padding: '0.375rem 0.75rem', borderRadius: 8, border: '1px solid var(--color-border)',
                  background: 'var(--color-bg-card)', color: 'var(--color-text-secondary)',
                  fontSize: '0.8125rem', cursor: 'pointer', fontWeight: 600,
                  display: 'flex', alignItems: 'center', gap: '0.375rem',
                }}
              >
                <RefreshCw size={13} style={{ animation: loadingScanEmails ? 'spin 1s linear infinite' : 'none' }} />
                Reload
              </button>
            </div>
          </div>

          {/* List of Scan Emails */}
          {scanEmails.length === 0 ? (
            <div className="card" style={{ textAlign: 'center', padding: '3.5rem 1rem', color: 'var(--color-text-muted)' }}>
              <Mail size={40} style={{ opacity: 0.3, marginBottom: '0.75rem' }} />
              <div style={{ fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.25rem' }}>No Email Findings In Current Scan</div>
              <div style={{ fontSize: '0.8125rem' }}>
                Run a live domain scan with GitHub/Hunter providers, or use the "Live OSINT Search" tab above to investigate any email.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {scanEmails
                .filter(e => !scanFilter || e.value?.toLowerCase().includes(scanFilter.toLowerCase()) || e.description?.toLowerCase().includes(scanFilter.toLowerCase()))
                .map(finding => {
                  const sources = finding.sources || [finding.source];
                  const sc = finding.source_count || sources.length;

                  return (
                    <div
                      key={finding.id}
                      className="card"
                      style={{
                        padding: '1.125rem 1.25rem',
                        display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                        <div style={{
                          width: 42, height: 42, borderRadius: 10,
                          background: 'rgba(0, 212, 255, 0.1)', border: '1px solid rgba(0, 212, 255, 0.2)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        }}>
                          <Mail size={18} color="var(--color-cyber-blue)" />
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span style={{ fontSize: '0.9375rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>
                              {finding.value}
                            </span>
                            {sc > 1 && (
                              <span style={{
                                padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.6875rem',
                                background: 'rgba(34, 197, 94, 0.1)', color: '#22c55e', fontWeight: 700,
                              }}>
                                {sc} sources
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
                            {finding.description?.slice(0, 90)}
                          </div>
                          <div style={{ display: 'flex', gap: '0.375rem', marginTop: '0.5rem' }}>
                            {sources.map(s => <SourcePill key={s} source={s} />)}
                          </div>
                        </div>
                      </div>

                      {/* Action: Investigate with Live OSINT */}
                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <button
                          onClick={() => setSelectedFinding(finding)}
                          style={{
                            padding: '0.375rem 0.75rem', borderRadius: 8, fontSize: '0.75rem',
                            background: 'rgba(255, 255, 255, 0.04)', border: '1px solid var(--color-border)',
                            color: 'var(--color-text-secondary)', cursor: 'pointer', fontWeight: 600,
                          }}
                        >
                          Evidence
                        </button>
                        <button
                          onClick={() => handleSearch(finding.value)}
                          style={{
                            display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                            padding: '0.45rem 1rem', borderRadius: 8, fontSize: '0.8125rem',
                            background: 'var(--color-cyber-blue)', color: '#0a0e1a',
                            border: 'none', cursor: 'pointer', fontWeight: 700,
                          }}
                        >
                          <Sparkles size={14} /> Investigate OSINT
                        </button>
                      </div>
                    </div>
                  );
                })}
            </div>
          )}
        </div>
      )}

      {/* Evidence Modal */}
      {selectedFinding && (
        <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
