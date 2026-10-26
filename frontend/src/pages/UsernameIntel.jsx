import { useState, useEffect } from 'react';
import {
  User, Search, GitBranch, Globe, ExternalLink, Download, FileSpreadsheet,
  Building, MapPin, Clock, ShieldCheck, ShieldAlert, AlertCircle, RefreshCw,
  Layers, Sparkles, Database, Check, ChevronRight, Lock, Key, FileText,
  Target, ArrowRight, ShieldX, Terminal, Filter, CheckCircle2, XCircle,
  Info, Activity, Code2, Star, GitFork, Mail, AlertTriangle, Shield
} from 'lucide-react';
import useScanStore from '../stores/scanStore';
import { getUsernames, lookupUsername, downloadUsernameExcel } from '../services/api';
import { exportUsernameIntelToExcel } from '../utils/excelExport';
import EvidenceModal from '../components/common/EvidenceModal';

function SourcePill({ source }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
      padding: '0.2rem 0.6rem', borderRadius: 9999, fontSize: '0.6875rem', fontWeight: 600,
      background: 'rgba(139, 92, 246, 0.08)', color: '#8b5cf6',
      border: '1px solid rgba(139, 92, 246, 0.2)', fontFamily: 'var(--font-mono)',
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

export default function UsernameIntel() {
  const { currentScan } = useScanStore();
  const activeScanId = currentScan?.id || null;

  // Tabs: 'search' (Live OSINT Investigator) or 'scan' (Discovered scan findings)
  const [activeTab, setActiveTab] = useState('search');

  // Search state
  const [targetUsername, setTargetUsername] = useState('');
  const [intelData, setIntelData] = useState(null);
  const [isSearching, setIsSearching] = useState(false);
  const [searchError, setSearchError] = useState(null);
  const [exporting, setExporting] = useState(false);

  // Scan identities state
  const [scanIdentities, setScanIdentities] = useState([]);
  const [loadingScanIdentities, setLoadingScanIdentities] = useState(false);
  const [scanFilter, setScanFilter] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Active view tab inside result dossier
  const [dossierTab, setDossierTab] = useState('profile'); // 'profile' | 'accounts' | 'repos' | 'emails' | 'posture' | 'web'

  // Posture sub-tabs
  const [postureSubTab, setPostureSubTab] = useState('overview'); // 'overview' | 'scenarios' | 'matrix'
  const [matrixFilter, setMatrixFilter] = useState('ALL');
  const [platformCategoryFilter, setPlatformCategoryFilter] = useState('ALL');

  // Load scan identities if available
  useEffect(() => {
    if (activeScanId) {
      loadScanIdentitiesData();
    }
  }, [activeScanId]);

  const loadScanIdentitiesData = async () => {
    if (!activeScanId) return;
    setLoadingScanIdentities(true);
    try {
      const data = await getUsernames(activeScanId);
      setScanIdentities(data || []);
    } catch {
      setScanIdentities([]);
    }
    setLoadingScanIdentities(false);
  };

  const handleSearch = async (handleToSearch) => {
    const raw = (handleToSearch || targetUsername || '').trim().replace(/^@/, '');
    if (!raw) return;

    setIsSearching(true);
    setSearchError(null);
    setTargetUsername(raw);
    setActiveTab('search');

    try {
      const result = await lookupUsername(raw);
      if (result.error && !result.sources_queried) {
        setSearchError(result.error);
        setIntelData(null);
      } else {
        setIntelData(result);
        setDossierTab('profile');
      }
    } catch (err) {
      setSearchError(err.response?.data?.detail || err.message || 'Failed to query live username intelligence.');
      setIntelData(null);
    } finally {
      setIsSearching(false);
    }
  };

  const handleExportExcel = async () => {
    if (!intelData) return;
    setExporting(true);
    try {
      exportUsernameIntelToExcel(intelData);
    } catch (err) {
      console.error('Client Excel export failed, falling back to server:', err);
      try {
        const blob = await downloadUsernameExcel(intelData.username, intelData);
        const url = window.URL.createObjectURL(new Blob([blob]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `Username_Intel_${intelData.username}.xlsx`);
        document.body.appendChild(link);
        link.click();
        link.parentNode.removeChild(link);
      } catch (srvErr) {
        alert('Failed to generate Excel report: ' + srvErr.message);
      }
    } finally {
      setExporting(false);
    }
  };

  const handleExportJSON = () => {
    if (!intelData) return;
    const blob = new Blob([JSON.stringify(intelData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Username_Intel_${intelData.username}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const profile = intelData?.profile || {};
  const postureData = intelData?.security_posture || {
    composite_score: 0,
    health_score: 100,
    grade: 'C',
    badge_color: '#38bdf8',
    risk_level: 'MODERATE RISK',
    verdict: 'No assessment generated.',
    pillars: {},
    attack_scenarios: [],
    posture_matrix: [],
  };
  const repos = intelData?.repos?.repos || [];
  const topLanguages = intelData?.repos?.top_languages || [];
  const probes = intelData?.platform_probes || [];
  const foundProbes = probes.filter(p => p.exists);
  const commits = intelData?.events?.commits || [];
  const uncoveredEmails = intelData?.uncovered_emails || [];
  const breachedEmails = intelData?.breached_emails || [];
  const gists = intelData?.gists?.gists || [];
  const sshKeys = intelData?.keys?.ssh_keys || [];
  const webpages = intelData?.web_pages?.pages || [];

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', paddingBottom: '3rem' }} className="animate-fade-in">
      {/* ── Page Header ── */}
      <div style={{ marginBottom: '1.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
            <div style={{
              width: 44, height: 44, borderRadius: 12,
              background: 'linear-gradient(135deg, rgba(139, 92, 246, 0.2), rgba(0, 212, 255, 0.2))',
              border: '1px solid rgba(139, 92, 246, 0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <User size={22} color="#8b5cf6" />
            </div>
            <div>
              <h1 style={{ margin: 0, fontSize: '1.625rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                Username Intelligence
              </h1>
              <p style={{ margin: 0, fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
                Passive developer profiling, cross-platform account correlation, commit email extraction & security posture
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
              padding: '0.25rem 0.625rem', borderRadius: 9999, fontSize: '0.75rem',
              background: 'rgba(34, 197, 94, 0.1)', color: '#22c55e', border: '1px solid rgba(34, 197, 94, 0.25)',
              fontWeight: 600,
            }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', display: 'inline-block' }} />
              Passive OSINT Mode
            </span>
          </div>
        </div>

        {/* Mode Switch Tabs */}
        <div style={{
          display: 'flex', gap: '0.5rem', marginTop: '1.25rem',
          borderBottom: '1px solid var(--color-border)', paddingBottom: '0.75rem',
        }}>
          <button
            onClick={() => setActiveTab('search')}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.5rem',
              padding: '0.5rem 1rem', borderRadius: 8, fontSize: '0.875rem', fontWeight: 600,
              background: activeTab === 'search' ? 'rgba(139, 92, 246, 0.15)' : 'transparent',
              color: activeTab === 'search' ? '#8b5cf6' : 'var(--color-text-secondary)',
              border: `1px solid ${activeTab === 'search' ? 'rgba(139, 92, 246, 0.3)' : 'transparent'}`,
              cursor: 'pointer', transition: 'all 0.15s ease',
            }}
          >
            <Sparkles size={16} /> Live OSINT Investigator
          </button>

          <button
            onClick={() => setActiveTab('scan')}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.5rem',
              padding: '0.5rem 1rem', borderRadius: 8, fontSize: '0.875rem', fontWeight: 600,
              background: activeTab === 'scan' ? 'rgba(139, 92, 246, 0.15)' : 'transparent',
              color: activeTab === 'scan' ? '#8b5cf6' : 'var(--color-text-secondary)',
              border: `1px solid ${activeTab === 'scan' ? 'rgba(139, 92, 246, 0.3)' : 'transparent'}`,
              cursor: 'pointer', transition: 'all 0.15s ease',
            }}
          >
            <Database size={16} /> Scan Findings ({scanIdentities.length})
          </button>
        </div>
      </div>

      {/* ═════════════════════ TAB 1: LIVE OSINT SEARCH ═════════════════════ */}
      {activeTab === 'search' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Search Box */}
          <div className="card" style={{ padding: '1.25rem' }}>
            <form
              onSubmit={(e) => { e.preventDefault(); handleSearch(); }}
              style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}
            >
              <div style={{
                flex: 1, minWidth: 260, display: 'flex', alignItems: 'center', gap: '0.625rem',
                background: 'var(--color-bg-input)', border: '1px solid var(--color-border)',
                borderRadius: 8, padding: '0.5rem 0.875rem',
              }}>
                <span style={{ fontSize: '0.9375rem', color: '#8b5cf6', fontWeight: 700 }}>@</span>
                <input
                  type="text"
                  placeholder="Enter target username or handle (e.g. torvalds, octocat, apexnova_dev)..."
                  value={targetUsername}
                  onChange={(e) => setTargetUsername(e.target.value)}
                  disabled={isSearching}
                  style={{
                    flex: 1, background: 'none', border: 'none', outline: 'none',
                    color: 'var(--color-text-primary)', fontSize: '0.875rem',
                  }}
                />
              </div>

              <button
                type="submit"
                disabled={isSearching || !targetUsername.trim()}
                className="btn-primary"
                style={{
                  display: 'flex', alignItems: 'center', gap: '0.5rem',
                  padding: '0.625rem 1.25rem', borderRadius: 8, fontSize: '0.875rem', fontWeight: 700,
                  cursor: isSearching || !targetUsername.trim() ? 'not-allowed' : 'pointer',
                  opacity: isSearching || !targetUsername.trim() ? 0.6 : 1,
                  background: 'linear-gradient(135deg, #8b5cf6, #00d4ff)', color: '#0a0e1a', border: 'none',
                }}
              >
                {isSearching ? <RefreshCw size={16} className="animate-spin" /> : <Search size={16} />}
                {isSearching ? 'Investigating...' : 'Investigate Username'}
              </button>

              {intelData && (
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    type="button"
                    onClick={handleExportExcel}
                    disabled={exporting}
                    className="btn-secondary"
                    title="Export multi-sheet Excel dossier"
                    style={{
                      display: 'flex', alignItems: 'center', gap: '0.375rem',
                      padding: '0.625rem 0.875rem', borderRadius: 8, fontSize: '0.8125rem', fontWeight: 600,
                      cursor: 'pointer', background: 'rgba(34, 197, 94, 0.1)', color: '#22c55e',
                      border: '1px solid rgba(34, 197, 94, 0.3)',
                    }}
                  >
                    <FileSpreadsheet size={15} />
                    {exporting ? 'Generating...' : 'Excel (.xlsx)'}
                  </button>

                  <button
                    type="button"
                    onClick={handleExportJSON}
                    className="btn-secondary"
                    title="Export raw JSON"
                    style={{
                      display: 'flex', alignItems: 'center', gap: '0.375rem',
                      padding: '0.625rem 0.875rem', borderRadius: 8, fontSize: '0.8125rem', fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    <Download size={15} /> JSON
                  </button>
                </div>
              )}
            </form>

            {/* Quick Suggestion Chips */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.75rem',
              flexWrap: 'wrap', fontSize: '0.75rem', color: 'var(--color-text-muted)',
            }}>
              <span>Try test profiles:</span>
              {['torvalds', 'octocat', 'apexnova_dev', 'defcon'].map(ex => (
                <button
                  key={ex}
                  type="button"
                  onClick={() => { setTargetUsername(ex); handleSearch(ex); }}
                  style={{
                    background: 'rgba(255, 255, 255, 0.04)', border: '1px solid var(--color-border)',
                    borderRadius: 9999, padding: '0.2rem 0.5rem', fontSize: '0.6875rem',
                    color: 'var(--color-text-secondary)', cursor: 'pointer', fontFamily: 'var(--font-mono)',
                  }}
                >
                  @{ex}
                </button>
              ))}
            </div>
          </div>

          {/* Search Error */}
          {searchError && (
            <div style={{
              padding: '0.875rem 1rem', borderRadius: 8,
              background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)',
              display: 'flex', alignItems: 'center', gap: '0.75rem', color: '#ef4444', fontSize: '0.875rem',
            }}>
              <AlertCircle size={18} style={{ flexShrink: 0 }} />
              <div>{searchError}</div>
            </div>
          )}

          {/* Initial State / Prompt */}
          {!intelData && !isSearching && !searchError && (
            <div className="card" style={{ textAlign: 'center', padding: '3.5rem 1rem', color: 'var(--color-text-muted)' }}>
              <User size={48} style={{ opacity: 0.3, marginBottom: '1rem', color: '#8b5cf6' }} />
              <h3 style={{ margin: '0 0 0.5rem', color: 'var(--color-text-primary)', fontSize: '1.125rem' }}>
                Passive Identity & Developer Intelligence Engine
              </h3>
              <p style={{ maxWidth: 520, margin: '0 auto 1.5rem', fontSize: '0.875rem', lineHeight: 1.5 }}>
                Enter any developer username or handle to inspect public GitHub commits, uncover embedded author emails, probe cross-platform presence across 20+ services, and generate an executive risk posture.
              </p>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', borderRadius: 6, background: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)' }}>
                  🔍 Commit Author Emails
                </span>
                <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', borderRadius: 6, background: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)' }}>
                  🌐 Cross-Platform Probing
                </span>
                <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', borderRadius: 6, background: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)' }}>
                  🔑 SSH Key Comments
                </span>
                <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', borderRadius: 6, background: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)' }}>
                  🛡️ Breach Cross-Correlation
                </span>
                <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', borderRadius: 6, background: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)' }}>
                  📊 Security Posture Matrix
                </span>
              </div>
            </div>
          )}

          {/* ═════════════════════ RESULTS DOSSIER VIEW ═════════════════════ */}
          {intelData && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Identity Header Card */}
              <div className="card" style={{
                padding: '1.5rem',
                background: 'linear-gradient(135deg, rgba(20, 26, 41, 0.95), rgba(15, 23, 42, 0.95))',
                border: '1px solid rgba(139, 92, 246, 0.3)',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1.25rem' }}>
                  <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'center' }}>
                    {profile.avatar_url ? (
                      <img
                        src={profile.avatar_url}
                        alt={intelData.username}
                        style={{
                          width: 72, height: 72, borderRadius: 16,
                          border: '2px solid rgba(139, 92, 246, 0.4)',
                          objectFit: 'cover', background: 'var(--color-bg-secondary)',
                        }}
                      />
                    ) : (
                      <div style={{
                        width: 72, height: 72, borderRadius: 16,
                        background: 'rgba(139, 92, 246, 0.15)', border: '2px solid rgba(139, 92, 246, 0.3)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                      }}>
                        <User size={36} color="#8b5cf6" />
                      </div>
                    )}

                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', flexWrap: 'wrap' }}>
                        <h2 style={{ margin: 0, fontSize: '1.375rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                          {profile.name || `@${intelData.username}`}
                        </h2>
                        <span style={{
                          fontSize: '0.8125rem', color: '#8b5cf6', fontFamily: 'var(--font-mono)', fontWeight: 700,
                        }}>
                          @{intelData.username}
                        </span>
                        {profile.hireable && (
                          <span style={{
                            padding: '0.15rem 0.5rem', borderRadius: 9999, fontSize: '0.6875rem',
                            background: 'rgba(34, 197, 94, 0.15)', color: '#22c55e', fontWeight: 700,
                          }}>
                            Hireable
                          </span>
                        )}
                        {intelData.is_demo && (
                          <span style={{
                            padding: '0.15rem 0.5rem', borderRadius: 9999, fontSize: '0.6875rem',
                            background: 'rgba(234, 88, 12, 0.15)', color: '#ea580c', fontWeight: 700,
                          }}>
                            Demo Simulation
                          </span>
                        )}
                      </div>

                      {profile.bio && (
                        <p style={{ margin: '0.35rem 0 0.5rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', maxWidth: 640 }}>
                          {profile.bio}
                        </p>
                      )}

                      {/* Attribute Pills */}
                      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '0.35rem' }}>
                        {profile.company && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                            <Building size={13} color="var(--color-cyber-blue)" /> {profile.company}
                          </span>
                        )}
                        {profile.location && (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                            <MapPin size={13} color="#ea580c" /> {profile.location}
                          </span>
                        )}
                        {profile.blog && (
                          <a
                            href={profile.blog.startsWith('http') ? profile.blog : `https://${profile.blog}`}
                            target="_blank" rel="noopener noreferrer"
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: 'var(--color-cyber-blue)', textDecoration: 'none' }}
                          >
                            <Globe size={13} /> {profile.blog.replace(/^https?:\/\//, '')}
                          </a>
                        )}
                        {profile.twitter_username && (
                          <a
                            href={`https://x.com/${profile.twitter_username}`}
                            target="_blank" rel="noopener noreferrer"
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: '#38bdf8', textDecoration: 'none' }}
                          >
                            <ExternalLink size={13} /> @{profile.twitter_username}
                          </a>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Posture Score Mini-Badge */}
                  <div style={{
                    padding: '0.75rem 1.125rem', borderRadius: 10,
                    background: 'rgba(0, 0, 0, 0.35)', border: '1px solid var(--color-border)',
                    textAlign: 'center', minWidth: 140,
                  }}>
                    <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                      Threat Index
                    </div>
                    <div style={{ fontSize: '1.75rem', fontWeight: 900, color: postureData.badge_color || '#38bdf8', lineHeight: 1.1 }}>
                      {postureData.composite_score}
                      <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-muted)' }}>/100</span>
                    </div>
                    <div style={{ fontSize: '0.6875rem', fontWeight: 800, color: postureData.badge_color || '#38bdf8', marginTop: 2 }}>
                      GRADE {postureData.grade} • {postureData.risk_level}
                    </div>
                  </div>
                </div>

                {/* Sources Strip */}
                <div style={{
                  display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap',
                  marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontWeight: 600 }}>
                    Sources Queried ({intelData.sources_successful?.length || 0}/{intelData.sources_queried?.length || 0}):
                  </span>
                  {(intelData.sources_successful || []).map(src => (
                    <SourcePill key={src} source={src} />
                  ))}
                </div>
              </div>

              {/* Dossier Navigation Tabs */}
              <div style={{
                display: 'flex', gap: '0.375rem', background: 'var(--color-bg-secondary)',
                padding: '0.375rem', borderRadius: 10, border: '1px solid var(--color-border)',
                flexWrap: 'wrap',
              }}>
                {[
                  { id: 'profile', label: 'Developer Profile', icon: User },
                  { id: 'accounts', label: `Platform Accounts (${foundProbes.length})`, icon: Globe },
                  { id: 'repos', label: `Repositories & Tech (${repos.length})`, icon: GitBranch },
                  { id: 'emails', label: `Uncovered Emails (${uncoveredEmails.length})`, icon: Mail },
                  { id: 'posture', label: 'Reputation & Posture', icon: ShieldCheck, badge: `Grade ${postureData.grade}` },
                  { id: 'web', label: `Web Mentions (${webpages.length})`, icon: FileText },
                ].map(tab => {
                  const Icon = tab.icon;
                  const active = dossierTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setDossierTab(tab.id)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: '0.375rem',
                        padding: '0.5rem 0.875rem', borderRadius: 7, fontSize: '0.8125rem', fontWeight: 700,
                        background: active ? '#8b5cf6' : 'transparent',
                        color: active ? '#fff' : 'var(--color-text-secondary)',
                        border: 'none', cursor: 'pointer', transition: 'all 0.15s ease',
                      }}
                    >
                      <Icon size={14} />
                      {tab.label}
                      {tab.badge && (
                        <span style={{
                          padding: '0.1rem 0.4rem', borderRadius: 9999, fontSize: '0.6875rem',
                          background: active ? 'rgba(255, 255, 255, 0.2)' : 'rgba(139, 92, 246, 0.15)',
                          color: active ? '#fff' : '#8b5cf6', fontWeight: 800,
                        }}>
                          {tab.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>

              {/* ───────────────── DOSSIER TAB 1: DEVELOPER PROFILE ───────────────── */}
              {dossierTab === 'profile' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
                    {/* Activity & Stats Card */}
                    <div className="card" style={{ padding: '1.25rem' }}>
                      <h3 style={{ margin: '0 0 1rem', fontSize: '0.9375rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                        Developer Statistics
                      </h3>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem' }}>
                        <div style={{ padding: '0.875rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                            Public Repositories
                          </div>
                          <div style={{ fontSize: '1.375rem', fontWeight: 800, color: 'var(--color-cyber-blue)', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
                            {profile.public_repos || 0}
                          </div>
                        </div>

                        <div style={{ padding: '0.875rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                            Public Gists
                          </div>
                          <div style={{ fontSize: '1.375rem', fontWeight: 800, color: '#8b5cf6', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
                            {profile.public_gists || 0}
                          </div>
                        </div>

                        <div style={{ padding: '0.875rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                            Followers
                          </div>
                          <div style={{ fontSize: '1.375rem', fontWeight: 800, color: '#22c55e', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
                            {profile.followers || 0}
                          </div>
                        </div>

                        <div style={{ padding: '0.875rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                          <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                            Following
                          </div>
                          <div style={{ fontSize: '1.375rem', fontWeight: 800, color: 'var(--color-text-secondary)', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
                            {profile.following || 0}
                          </div>
                        </div>
                      </div>

                      <div style={{ marginTop: '1rem', paddingTop: '0.875rem', borderTop: '1px solid var(--color-border)', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                        <div>Account Created: <strong>{profile.created_at ? new Date(profile.created_at).toLocaleDateString() : 'N/A'}</strong></div>
                        <div style={{ marginTop: '0.25rem' }}>Profile Last Updated: <strong>{profile.updated_at ? new Date(profile.updated_at).toLocaleDateString() : 'N/A'}</strong></div>
                      </div>
                    </div>

                    {/* Cryptography & Keys Card */}
                    <div className="card" style={{ padding: '1.25rem' }}>
                      <h3 style={{ margin: '0 0 1rem', fontSize: '0.9375rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                        Public Cryptographic Keys & Hardware
                      </h3>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        <div style={{
                          padding: '0.875rem', borderRadius: 8,
                          background: intelData.keys?.has_gpg_key ? 'rgba(34, 197, 94, 0.08)' : 'var(--color-bg-secondary)',
                          border: `1px solid ${intelData.keys?.has_gpg_key ? 'rgba(34, 197, 94, 0.25)' : 'var(--color-border)'}`,
                          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <Key size={16} color={intelData.keys?.has_gpg_key ? '#22c55e' : 'var(--color-text-muted)'} />
                            <div>
                              <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                                PGP Commit Signing Key
                              </div>
                              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                                {intelData.keys?.has_gpg_key ? 'Public GPG key block published on GitHub' : 'No public GPG key configured'}
                              </div>
                            </div>
                          </div>
                          <RiskBadge
                            label={intelData.keys?.has_gpg_key ? 'VERIFIED' : 'UNVERIFIED'}
                            isPositive={intelData.keys?.has_gpg_key}
                            isNeutral={!intelData.keys?.has_gpg_key}
                          />
                        </div>

                        <div style={{
                          padding: '0.875rem', borderRadius: 8, background: 'var(--color-bg-secondary)',
                          border: '1px solid var(--color-border)',
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                            <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                              Configured SSH Public Keys ({sshKeys.length})
                            </span>
                            <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                              From https://github.com/{intelData.username}.keys
                            </span>
                          </div>

                          {sshKeys.length === 0 ? (
                            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                              No public SSH keys found on GitHub profile.
                            </div>
                          ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                              {sshKeys.map((k, idx) => (
                                <div key={idx} style={{
                                  padding: '0.5rem 0.625rem', borderRadius: 6, background: 'var(--color-bg-input)',
                                  border: '1px solid var(--color-border)', fontSize: '0.75rem',
                                }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                    <strong style={{ color: 'var(--color-cyber-blue)' }}>{k.type}</strong>
                                    {k.comment && (
                                      <span style={{ color: '#ea580c', fontFamily: 'var(--font-mono)', fontSize: '0.6875rem' }}>
                                        {k.comment}
                                      </span>
                                    )}
                                  </div>
                                  <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)', fontSize: '0.6875rem', marginTop: 2 }}>
                                    {k.raw}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Organizations Card */}
                  {intelData.orgs?.orgs?.length > 0 && (
                    <div className="card" style={{ padding: '1.25rem' }}>
                      <h3 style={{ margin: '0 0 1rem', fontSize: '0.9375rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                        Public Organizations & Teams ({intelData.orgs.orgs.length})
                      </h3>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '0.75rem' }}>
                        {intelData.orgs.orgs.map((org, idx) => (
                          <div key={idx} style={{
                            padding: '0.75rem 1rem', borderRadius: 8, background: 'var(--color-bg-secondary)',
                            border: '1px solid var(--color-border)', display: 'flex', alignItems: 'center', gap: '0.75rem',
                          }}>
                            {org.avatar_url && (
                              <img src={org.avatar_url} alt={org.login} style={{ width: 32, height: 32, borderRadius: 8 }} />
                            )}
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <a
                                href={org.url} target="_blank" rel="noopener noreferrer"
                                style={{ fontWeight: 700, color: 'var(--color-text-primary)', fontSize: '0.8125rem', textDecoration: 'none' }}
                              >
                                {org.login}
                              </a>
                              {org.description && (
                                <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {org.description}
                                </div>
                              )}
                            </div>
                            <ExternalLink size={12} color="var(--color-text-muted)" />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ───────────────── DOSSIER TAB 2: PLATFORM ACCOUNTS ───────────────── */}
              {dossierTab === 'accounts' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  {/* Category Filter Pills */}
                  <div style={{ display: 'flex', gap: '0.375rem', flexWrap: 'wrap' }}>
                    {['ALL', 'Developer & Code', 'Package Registry', 'Security & Bug Bounty', 'Social & Community', 'Identity & Cryptography', 'Container & Cloud'].map(cat => (
                      <button
                        key={cat}
                        onClick={() => setPlatformCategoryFilter(cat)}
                        style={{
                          padding: '0.35rem 0.75rem', borderRadius: 9999, fontSize: '0.75rem', fontWeight: 700,
                          border: 'none', cursor: 'pointer',
                          background: platformCategoryFilter === cat ? '#8b5cf6' : 'var(--color-bg-secondary)',
                          color: platformCategoryFilter === cat ? '#fff' : 'var(--color-text-secondary)',
                        }}
                      >
                        {cat}
                      </button>
                    ))}
                  </div>

                  {/* Platform Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '0.875rem' }}>
                    {probes
                      .filter(p => platformCategoryFilter === 'ALL' || p.category.includes(platformCategoryFilter) || platformCategoryFilter.includes(p.category))
                      .map((p, idx) => {
                        const isFound = p.exists;
                        return (
                          <div
                            key={idx}
                            className="card"
                            style={{
                              padding: '1rem 1.125rem',
                              borderLeft: `3px solid ${isFound ? '#22c55e' : 'var(--color-border)'}`,
                              background: isFound ? 'rgba(34, 197, 94, 0.04)' : 'var(--color-bg-card)',
                              opacity: isFound ? 1 : 0.65,
                            }}
                          >
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                              <div>
                                <div style={{ fontSize: '0.9375rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                                  {p.platform}
                                </div>
                                <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                                  {p.category}
                                </span>
                              </div>

                              <span style={{
                                padding: '0.15rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 800,
                                background: isFound ? 'rgba(34, 197, 94, 0.15)' : 'rgba(148, 163, 184, 0.12)',
                                color: isFound ? '#22c55e' : 'var(--color-text-muted)',
                              }}>
                                {isFound ? 'FOUND' : 'NOT FOUND'}
                              </span>
                            </div>

                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.75rem', paddingTop: '0.5rem', borderTop: '1px solid var(--color-border)' }}>
                              <span style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
                                HTTP {p.status_code || 0}
                              </span>

                              {isFound ? (
                                <a
                                  href={p.profile_url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  style={{
                                    display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
                                    fontSize: '0.75rem', fontWeight: 700, color: '#8b5cf6', textDecoration: 'none',
                                  }}
                                >
                                  Open Profile <ExternalLink size={12} />
                                </a>
                              ) : (
                                <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                                  Available Handle
                                </span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                  </div>
                </div>
              )}

              {/* ───────────────── DOSSIER TAB 3: REPOSITORIES & TECH ───────────────── */}
              {dossierTab === 'repos' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  {/* Top Tech Languages Bar */}
                  {topLanguages.length > 0 && (
                    <div className="card" style={{ padding: '1.25rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                        <h4 style={{ margin: 0, fontSize: '0.875rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                          Primary Tech Stack & Code Languages
                        </h4>
                        <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                          Aggregated from public repositories
                        </span>
                      </div>

                      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                        {topLanguages.map(lang => (
                          <span
                            key={lang}
                            style={{
                              padding: '0.35rem 0.75rem', borderRadius: 8, fontSize: '0.8125rem', fontWeight: 700,
                              background: 'rgba(0, 212, 255, 0.1)', color: 'var(--color-cyber-blue)',
                              border: '1px solid rgba(0, 212, 255, 0.25)', display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
                            }}
                          >
                            <Code2 size={13} /> {lang}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Repositories List */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
                    {repos.map((r, idx) => (
                      <div key={idx} className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                            <a
                              href={r.url} target="_blank" rel="noopener noreferrer"
                              style={{ fontWeight: 800, fontSize: '0.9375rem', color: 'var(--color-cyber-blue)', textDecoration: 'none' }}
                            >
                              {r.name}
                            </a>
                            <span style={{
                              padding: '0.15rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 700,
                              background: 'rgba(139, 92, 246, 0.12)', color: '#8b5cf6',
                            }}>
                              {r.language || 'Other'}
                            </span>
                          </div>

                          <p style={{ margin: '0 0 0.875rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.45 }}>
                            {r.description || 'No description provided.'}
                          </p>

                          {r.topics?.length > 0 && (
                            <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
                              {r.topics.slice(0, 4).map(t => (
                                <span key={t} style={{
                                  fontSize: '0.625rem', padding: '0.1rem 0.4rem', borderRadius: 4,
                                  background: 'var(--color-bg-secondary)', color: 'var(--color-text-muted)',
                                }}>
                                  #{t}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '0.75rem', borderTop: '1px solid var(--color-border)', fontSize: '0.75rem' }}>
                          <div style={{ display: 'flex', gap: '0.75rem', color: 'var(--color-text-muted)' }}>
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.2rem' }}>
                              <Star size={12} color="#f59e0b" /> {r.stars}
                            </span>
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.2rem' }}>
                              <GitFork size={12} /> {r.forks}
                            </span>
                          </div>
                          {r.license && (
                            <span style={{ color: 'var(--color-text-muted)', fontSize: '0.6875rem' }}>
                              {r.license}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Public Gists */}
                  {gists.length > 0 && (
                    <div className="card" style={{ padding: '1.25rem' }}>
                      <h4 style={{ margin: '0 0 1rem', fontSize: '0.875rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                        Public Gists & Code Pastes ({gists.length})
                      </h4>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
                        {gists.map((g, idx) => (
                          <div key={idx} style={{
                            padding: '0.75rem 1rem', borderRadius: 8, background: 'var(--color-bg-secondary)',
                            border: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                          }}>
                            <div>
                              <div style={{ fontWeight: 700, fontSize: '0.8125rem', color: 'var(--color-text-primary)' }}>
                                {g.description}
                              </div>
                              <div style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', marginTop: 2 }}>
                                Files: {g.files.join(', ')}
                              </div>
                            </div>
                            <a
                              href={g.url} target="_blank" rel="noopener noreferrer"
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', color: '#8b5cf6', fontSize: '0.75rem', fontWeight: 600, textDecoration: 'none' }}
                            >
                              View Gist <ExternalLink size={12} />
                            </a>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ───────────────── DOSSIER TAB 4: UNCOVERED EMAILS & BREACHES ───────────────── */}
              {dossierTab === 'emails' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  <div className="card" style={{ padding: '1.25rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                      <div>
                        <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                          Discovered Author Emails from Commit Logs & Key Metadata
                        </h3>
                        <p style={{ margin: '0.25rem 0 0', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                          Email addresses uncovered passively from Git PushEvent author fields and public SSH key comments.
                        </p>
                      </div>
                    </div>

                    {uncoveredEmails.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--color-text-muted)' }}>
                        <Mail size={32} style={{ opacity: 0.3, marginBottom: '0.5rem' }} />
                        <div>No personal email addresses exposed in public commit logs or keys.</div>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        {uncoveredEmails.map((em, idx) => {
                          const bInfo = breachedEmails.find(b => b.email === em);
                          const isBreached = bInfo?.breached;

                          return (
                            <div
                              key={idx}
                              style={{
                                padding: '1rem', borderRadius: 8,
                                background: isBreached ? 'rgba(239, 68, 68, 0.08)' : 'var(--color-bg-secondary)',
                                border: `1px solid ${isBreached ? 'rgba(239, 68, 68, 0.3)' : 'var(--color-border)'}`,
                                display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem',
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                <div style={{
                                  width: 38, height: 38, borderRadius: 10,
                                  background: isBreached ? 'rgba(239, 68, 68, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                                }}>
                                  <Mail size={18} color={isBreached ? '#ef4444' : '#22c55e'} />
                                </div>
                                <div>
                                  <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.875rem', color: 'var(--color-text-primary)' }}>
                                    {em}
                                  </div>
                                  <div style={{ fontSize: '0.6875rem', color: isBreached ? '#ef4444' : '#22c55e', fontWeight: 600, marginTop: 2 }}>
                                    {isBreached
                                      ? `Exposed in ${bInfo.breach_count} credential breach(es): ${bInfo.breaches.join(', ')}`
                                      : 'Clean record (No exposures found in XposedOrNot)'}
                                  </div>
                                </div>
                              </div>

                              <RiskBadge
                                label={isBreached ? `BREACHED (${bInfo.breach_count})` : 'CLEAN'}
                                isPositive={!isBreached}
                              />
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Commit Events Log */}
                  {commits.length > 0 && (
                    <div className="card" style={{ padding: '1.25rem' }}>
                      <h4 style={{ margin: '0 0 1rem', fontSize: '0.875rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                        Recent Public Commit Activity Logs ({commits.length})
                      </h4>
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
                          <thead>
                            <tr style={{ background: 'var(--color-bg-secondary)', borderBottom: '1px solid var(--color-border)' }}>
                              <th style={{ padding: '0.625rem 0.875rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem' }}>REPO</th>
                              <th style={{ padding: '0.625rem 0.875rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem' }}>MESSAGE</th>
                              <th style={{ padding: '0.625rem 0.875rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem' }}>AUTHOR</th>
                              <th style={{ padding: '0.625rem 0.875rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem' }}>EMAIL</th>
                              <th style={{ padding: '0.625rem 0.875rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem' }}>DATE</th>
                            </tr>
                          </thead>
                          <tbody>
                            {commits.map((c, idx) => (
                              <tr key={idx} style={{ borderBottom: '1px solid var(--color-border)' }}>
                                <td style={{ padding: '0.625rem 0.875rem', color: 'var(--color-cyber-blue)', fontWeight: 600 }}>
                                  {c.repo}
                                </td>
                                <td style={{ padding: '0.625rem 0.875rem', color: 'var(--color-text-primary)' }}>
                                  {c.message}
                                </td>
                                <td style={{ padding: '0.625rem 0.875rem', color: 'var(--color-text-secondary)' }}>
                                  {c.author_name}
                                </td>
                                <td style={{ padding: '0.625rem 0.875rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#ea580c' }}>
                                  {c.author_email}
                                </td>
                                <td style={{ padding: '0.625rem 0.875rem', color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>
                                  {c.date ? new Date(c.date).toLocaleDateString() : 'N/A'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ───────────────── DOSSIER TAB 5: REPUTATION & SECURITY POSTURE ───────────────── */}
              {dossierTab === 'posture' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  {/* Executive Hero Banner */}
                  <div className="card" style={{
                    padding: '1.5rem',
                    background: 'linear-gradient(135deg, rgba(20, 26, 41, 0.98), rgba(15, 23, 42, 0.98))',
                    border: `1px solid ${postureData.badge_color ? `${postureData.badge_color}44` : 'var(--color-border)'}`,
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1.25rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
                        <div style={{
                          width: 64, height: 64, borderRadius: 14,
                          background: `${postureData.badge_color}22`,
                          border: `2px solid ${postureData.badge_color}`,
                          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                        }}>
                          <span style={{ fontSize: '1.75rem', fontWeight: 900, color: postureData.badge_color, lineHeight: 1 }}>
                            {postureData.grade}
                          </span>
                          <span style={{ fontSize: '0.625rem', fontWeight: 800, color: postureData.badge_color, textTransform: 'uppercase' }}>
                            GRADE
                          </span>
                        </div>

                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                            <span style={{
                              padding: '0.2rem 0.6rem', borderRadius: 9999, fontSize: '0.75rem', fontWeight: 800,
                              background: `${postureData.badge_color}22`, color: postureData.badge_color,
                              border: `1px solid ${postureData.badge_color}44`,
                            }}>
                              {postureData.risk_level}
                            </span>
                            <span style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
                              Assessed for @{intelData.username}
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
                      <ShieldAlert size={18} color={postureData.badge_color || '#8b5cf6'} style={{ flexShrink: 0, marginTop: 2 }} />
                      <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-primary)', lineHeight: 1.55 }}>
                        <strong style={{ color: postureData.badge_color || '#8b5cf6' }}>Security Operations Verdict: </strong>
                        {postureData.verdict}
                      </div>
                    </div>
                  </div>

                  {/* Sub-Navigation Switcher */}
                  <div style={{
                    display: 'flex', gap: '0.375rem', background: 'var(--color-bg-secondary)',
                    padding: '0.375rem', borderRadius: 10, border: '1px solid var(--color-border)',
                  }}>
                    {[
                      { id: 'overview', label: 'Executive Dashboard', icon: Activity },
                      { id: 'scenarios', label: `Attack Scenarios (${postureData.attack_scenarios?.length || 0})`, icon: Target },
                      { id: 'matrix', label: `Controls Assessment (${postureData.posture_matrix?.length || 0})`, icon: Layers },
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
                            background: active ? '#8b5cf6' : 'transparent',
                            color: active ? '#fff' : 'var(--color-text-secondary)',
                            border: 'none', cursor: 'pointer',
                          }}
                        >
                          <SubIcon size={14} />
                          {sub.label}
                        </button>
                      );
                    })}
                  </div>

                  {/* ── Sub-Tab 1: Overview ── */}
                  {postureSubTab === 'overview' && (
                    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                      {/* 4 Security Pillars Grid */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
                        {Object.entries(postureData.pillars || {}).map(([key, pillar]) => {
                          const score = pillar.score || 0;
                          const statColor = score >= 75 ? '#ef4444' : score >= 50 ? '#ea580c' : score >= 30 ? '#f59e0b' : '#22c55e';

                          return (
                            <div key={key} className="card" style={{ padding: '1.25rem', borderTop: `3px solid ${statColor}` }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                                <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>
                                  {pillar.name}
                                </span>
                                <span style={{
                                  fontSize: '0.6875rem', fontWeight: 800, padding: '0.15rem 0.45rem',
                                  borderRadius: 4, background: `${statColor}18`, color: statColor,
                                }}>
                                  {pillar.status}
                                </span>
                              </div>

                              <div style={{ fontSize: '1.625rem', fontWeight: 900, color: statColor, margin: '0.25rem 0' }}>
                                {score}
                                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-text-muted)' }}>/100</span>
                              </div>

                              <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--color-text-secondary)', lineHeight: 1.45 }}>
                                {pillar.description}
                              </p>
                            </div>
                          );
                        })}
                      </div>

                      {/* Featured Attack Scenario Preview */}
                      {postureData.attack_scenarios?.[0] && (
                        <div className="card" style={{ padding: '1.25rem', borderLeft: '3px solid #ef4444' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                            <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>
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
                    </div>
                  )}

                  {/* ── Sub-Tab 2: Attack Scenarios ── */}
                  {postureSubTab === 'scenarios' && (
                    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      {(postureData.attack_scenarios || []).map((sc, scIdx) => (
                        <div key={scIdx} className="card" style={{
                          padding: '1.25rem',
                          borderLeft: `3px solid ${sc.severity.includes('CRITICAL') ? '#ef4444' : sc.severity.includes('HIGH') ? '#ea580c' : '#f59e0b'}`,
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', marginBottom: '0.5rem' }}>
                            <div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.25rem' }}>
                                <span style={{
                                  padding: '0.15rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 800,
                                  background: sc.severity.includes('CRITICAL') ? 'rgba(239, 68, 68, 0.15)' : 'rgba(234, 88, 12, 0.15)',
                                  color: sc.severity.includes('CRITICAL') ? '#ef4444' : '#ea580c',
                                }}>
                                  {sc.severity}
                                </span>
                                <span style={{
                                  padding: '0.15rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 800,
                                  background: 'rgba(0, 212, 255, 0.12)', color: 'var(--color-cyber-blue)',
                                }}>
                                  {sc.mitre_technique}
                                </span>
                              </div>
                              <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
                                {sc.title}
                              </h4>
                            </div>

                            <div style={{ textAlign: 'right', flexShrink: 0, fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                              <div>Likelihood: <strong style={{ color: 'var(--color-text-primary)' }}>{sc.likelihood}</strong></div>
                              <div>Impact: <strong style={{ color: 'var(--color-text-primary)' }}>{sc.impact}</strong></div>
                            </div>
                          </div>

                          <p style={{ margin: '0 0 1rem', fontSize: '0.8125rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                            {sc.description}
                          </p>

                          {/* Kill Chain Steps */}
                          <div style={{
                            padding: '0.875rem 1rem', borderRadius: 8, background: 'var(--color-bg-secondary)',
                            border: '1px solid var(--color-border)', marginBottom: '0.75rem',
                          }}>
                            <div style={{ fontSize: '0.6875rem', fontWeight: 800, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
                              Adversary Kill Chain Execution Path
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                              {(sc.kill_chain_steps || []).map((step, stIdx) => (
                                <div key={stIdx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--color-text-primary)' }}>
                                  <span style={{
                                    width: 18, height: 18, borderRadius: '50%', background: 'rgba(139, 92, 246, 0.2)',
                                    color: '#8b5cf6', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    fontSize: '0.625rem', fontWeight: 800, flexShrink: 0, marginTop: 1,
                                  }}>
                                    {stIdx + 1}
                                  </span>
                                  <span>{step}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Blue Team Mitigation */}
                          <div style={{
                            padding: '0.75rem 1rem', borderRadius: 8,
                            background: 'rgba(34, 197, 94, 0.08)', border: '1px solid rgba(34, 197, 94, 0.25)',
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

                  {/* ── Sub-Tab 3: Controls Assessment Matrix ── */}
                  {postureSubTab === 'matrix' && (
                    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      {/* Matrix Category Filter */}
                      <div style={{ display: 'flex', gap: '0.375rem', flexWrap: 'wrap' }}>
                        {['ALL', 'Email & Identity Privacy', 'Credential Integrity', 'Code Cryptography', 'SSH Authentication', 'Cross-Platform Exposure', 'Code Leakage Audit'].map(cat => (
                          <button
                            key={cat}
                            onClick={() => setMatrixFilter(cat)}
                            style={{
                              padding: '0.35rem 0.75rem', borderRadius: 9999, fontSize: '0.75rem', fontWeight: 700,
                              border: 'none', cursor: 'pointer',
                              background: matrixFilter === cat ? '#8b5cf6' : 'var(--color-bg-secondary)',
                              color: matrixFilter === cat ? '#fff' : 'var(--color-text-secondary)',
                            }}
                          >
                            {cat}
                          </button>
                        ))}
                      </div>

                      {/* Controls Table */}
                      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                        <div style={{ overflowX: 'auto' }}>
                          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
                            <thead>
                              <tr style={{ background: 'var(--color-bg-secondary)', borderBottom: '1px solid var(--color-border)' }}>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>STATUS</th>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>CONTROL / SIGNAL</th>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>OBSERVED FINDING</th>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>TECHNICAL IMPACT DETAIL</th>
                                <th style={{ padding: '0.75rem 1rem', color: 'var(--color-text-muted)', fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase' }}>HARDENING GUIDANCE</th>
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
                                    <tr key={mIdx} style={{ borderBottom: '1px solid var(--color-border)' }}>
                                      <td style={{ padding: '0.75rem 1rem', verticalAlign: 'top' }}>
                                        <span style={{
                                          display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
                                          padding: '0.2rem 0.5rem', borderRadius: 4, fontSize: '0.6875rem', fontWeight: 800,
                                          background: `${statColor}18`, color: statColor, border: `1px solid ${statColor}44`,
                                        }}>
                                          {isPass ? <CheckCircle2 size={10} /> : isFail ? <XCircle size={10} /> : <AlertTriangle size={10} />}
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

              {/* ───────────────── DOSSIER TAB 6: PUBLIC WEB MENTIONS ───────────────── */}
              {dossierTab === 'web' && (
                <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div className="card" style={{ padding: '1.25rem' }}>
                    <h3 style={{ margin: '0 0 1rem', fontSize: '0.9375rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                      Search Engine Mentions & Public Discussions ({webpages.length})
                    </h3>

                    {webpages.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--color-text-muted)' }}>
                        <FileText size={32} style={{ opacity: 0.3, marginBottom: '0.5rem' }} />
                        <div>No external public web pages found indexing this handle.</div>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        {webpages.map((p, idx) => (
                          <div
                            key={idx}
                            style={{
                              padding: '1rem', borderRadius: 8, background: 'var(--color-bg-secondary)',
                              border: '1px solid var(--color-border)',
                            }}
                          >
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.35rem' }}>
                              <a
                                href={p.url} target="_blank" rel="noopener noreferrer"
                                style={{ fontWeight: 700, fontSize: '0.875rem', color: 'var(--color-cyber-blue)', textDecoration: 'none' }}
                              >
                                {p.title}
                              </a>
                              <span style={{ fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
                                {p.source}
                              </span>
                            </div>

                            <p style={{ margin: '0 0 0.5rem', fontSize: '0.75rem', color: 'var(--color-text-secondary)', lineHeight: 1.45 }}>
                              {p.snippet}
                            </p>

                            <a
                              href={p.url} target="_blank" rel="noopener noreferrer"
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', color: '#8b5cf6', fontSize: '0.6875rem', fontWeight: 600, textDecoration: 'none' }}
                            >
                              {p.url} <ExternalLink size={10} />
                            </a>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═════════════════════ TAB 2: SCAN IDENTITIES ═════════════════════ */}
      {activeTab === 'scan' && (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Header filter & reload */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1.125rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                Identities Discovered in Active Scan ({scanIdentities.length})
              </h3>
              <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
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
                  placeholder="Filter scan usernames..."
                  style={{ background: 'none', border: 'none', outline: 'none', color: 'var(--color-text-primary)', fontSize: '0.8125rem', width: 170 }}
                />
              </div>

              <button
                onClick={loadScanIdentitiesData}
                disabled={!activeScanId || loadingScanIdentities}
                style={{
                  padding: '0.375rem 0.75rem', borderRadius: 8, border: '1px solid var(--color-border)',
                  background: 'var(--color-bg-card)', color: 'var(--color-text-secondary)',
                  fontSize: '0.8125rem', cursor: 'pointer', fontWeight: 600,
                  display: 'flex', alignItems: 'center', gap: '0.375rem',
                }}
              >
                <RefreshCw size={13} style={{ animation: loadingScanIdentities ? 'spin 1s linear infinite' : 'none' }} />
                Reload
              </button>
            </div>
          </div>

          {/* List of Scan Identities */}
          {scanIdentities.length === 0 ? (
            <div className="card" style={{ textAlign: 'center', padding: '3.5rem 1rem', color: 'var(--color-text-muted)' }}>
              <User size={40} style={{ opacity: 0.3, marginBottom: '0.75rem', color: '#8b5cf6' }} />
              <div style={{ fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.25rem' }}>No Username Findings In Current Scan</div>
              <div style={{ fontSize: '0.8125rem' }}>
                Run a live domain scan with GitHub/Hunter providers, or use the "Live OSINT Investigator" tab above to investigate any handle.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {scanIdentities
                .filter(i => !scanFilter || i.value?.toLowerCase().includes(scanFilter.toLowerCase()) || i.description?.toLowerCase().includes(scanFilter.toLowerCase()))
                .map(finding => {
                  const raw = finding.raw_data || {};
                  const login = raw.login || finding.value?.replace('github_org:', '').replace('github_user:', '');
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
                          background: 'rgba(139, 92, 246, 0.1)', border: '1px solid rgba(139, 92, 246, 0.2)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                        }}>
                          <User size={18} color="#8b5cf6" />
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span style={{ fontSize: '0.9375rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>
                              @{login || finding.value}
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

                      {/* Actions */}
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
                          onClick={() => handleSearch(login || finding.value)}
                          style={{
                            display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                            padding: '0.45rem 1rem', borderRadius: 8, fontSize: '0.8125rem',
                            background: 'linear-gradient(135deg, #8b5cf6, #00d4ff)', color: '#0a0e1a',
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
