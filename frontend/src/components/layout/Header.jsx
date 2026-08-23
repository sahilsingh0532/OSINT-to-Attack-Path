import { useState } from 'react';
import { Search, Play, Loader2, CheckCircle2, AlertTriangle, ToggleLeft, ToggleRight, Download } from 'lucide-react';
import useScanStore from '../../stores/scanStore';

export default function Header() {
  const [target, setTarget] = useState('apexnova.example');
  const [mode, setMode] = useState('demo');
  const { currentScan, startScan, isLoading, generateReport } = useScanStore();

  const handleScan = () => {
    if (target.trim()) {
      startScan(target.trim(), mode);
    }
  };

  const handleExport = async () => {
    if (currentScan?.id) {
      const report = await generateReport(currentScan.id);
      if (report) {
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `osint_report_${currentScan.target_domain}_${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    }
  };

  const isScanning = currentScan && !['completed', 'failed'].includes(currentScan.status);
  const progress = currentScan?.progress || 0;

  return (
    <header style={{
      height: 64,
      background: 'var(--color-bg-secondary)',
      borderBottom: '1px solid var(--color-border)',
      display: 'flex',
      alignItems: 'center',
      padding: '0 1.5rem',
      gap: '1rem',
      position: 'relative',
    }}>
      {/* Target Input */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, maxWidth: 480 }}>
        <Search size={16} color="var(--color-text-muted)" />
        <input
          className="input-field"
          style={{ flex: 1 }}
          type="text"
          placeholder="Enter target domain (e.g., apexnova.example)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleScan()}
          disabled={isScanning}
        />
      </div>

      {/* Mode Toggle */}
      <button
        onClick={() => setMode(mode === 'demo' ? 'live' : 'demo')}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.375rem',
          padding: '0.5rem 0.75rem',
          background: 'transparent',
          border: '1px solid var(--color-border)',
          borderRadius: '6px',
          color: mode === 'demo' ? 'var(--color-cyber-green)' : 'var(--color-cyber-blue)',
          cursor: 'pointer',
          fontSize: '0.75rem',
          fontWeight: 600,
        }}
      >
        {mode === 'demo' ? <ToggleLeft size={16} /> : <ToggleRight size={16} />}
        {mode === 'demo' ? 'Demo Mode' : 'Live Mode'}
      </button>

      {/* Scan Button */}
      <button
        className="btn-primary"
        onClick={handleScan}
        disabled={isScanning || !target.trim()}
      >
        {isScanning ? (
          <>
            <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />
            Scanning... {Math.round(progress * 100)}%
          </>
        ) : (
          <>
            <Play size={16} />
            Start Passive Reconnaissance
          </>
        )}
      </button>

      {/* Status */}
      {currentScan && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem' }}>
          {currentScan.status === 'completed' ? (
            <CheckCircle2 size={14} color="var(--color-cyber-green)" />
          ) : currentScan.status === 'failed' ? (
            <AlertTriangle size={14} color="var(--color-cyber-red)" />
          ) : null}
          <span style={{ color: 'var(--color-text-muted)' }}>
            {currentScan.status === 'completed' ? 'Complete' : currentScan.status === 'failed' ? 'Failed' : ''}
          </span>
        </div>
      )}

      {/* Export */}
      {currentScan?.status === 'completed' && (
        <button className="btn-secondary" onClick={handleExport} style={{ fontSize: '0.75rem', padding: '0.5rem 0.75rem' }}>
          <Download size={14} />
          Export
        </button>
      )}

      {/* Progress Bar */}
      {isScanning && (
        <div style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          height: 2,
          background: 'var(--color-border)',
        }}>
          <div style={{
            height: '100%',
            width: `${progress * 100}%`,
            background: 'linear-gradient(90deg, var(--color-cyber-blue), var(--color-cyber-green))',
            transition: 'width 0.3s ease',
          }} />
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </header>
  );
}
