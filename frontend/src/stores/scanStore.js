import { create } from 'zustand';
import * as api from '../services/api';

const useScanStore = create((set, get) => ({
  // State
  currentScan: null,
  scans: [],
  dashboardStats: null,
  findings: [],
  graphData: null,
  attackPaths: [],
  riskScores: [],
  riskSummary: null,
  recommendations: [],
  timeline: [],
  sources: [],
  report: null,
  isLoading: false,
  error: null,
  pollInterval: null,

  // Actions
  startScan: async (targetDomain, mode = 'demo') => {
    set({ isLoading: true, error: null });
    try {
      const scan = await api.createScan({ target_domain: targetDomain, mode });
      set({ currentScan: scan, isLoading: false });
      // Start polling for progress
      get().startPolling(scan.id);
      return scan;
    } catch (err) {
      set({ error: err.message, isLoading: false });
    }
  },

  startPolling: (scanId) => {
    const interval = setInterval(async () => {
      try {
        const scan = await api.getScan(scanId);
        set({ currentScan: scan });
        if (scan.status === 'completed' || scan.status === 'failed') {
          get().stopPolling();
          if (scan.status === 'completed') {
            get().loadAllData(scanId);
          }
        }
      } catch (err) {
        console.error('Poll error:', err);
      }
    }, 1000);
    set({ pollInterval: interval });
  },

  stopPolling: () => {
    const { pollInterval } = get();
    if (pollInterval) {
      clearInterval(pollInterval);
      set({ pollInterval: null });
    }
  },

  loadAllData: async (scanId) => {
    set({ isLoading: true });
    try {
      const [stats, findings, graphData, attackPaths, riskScores, riskSummary, recommendations, timeline] =
        await Promise.all([
          api.getDashboardStats(scanId),
          api.getFindings(scanId),
          api.getGraphData(scanId),
          api.getAttackPaths(scanId),
          api.getRiskScores(scanId),
          api.getRiskSummary(scanId),
          api.getRecommendations(scanId),
          api.getTimeline(scanId),
        ]);
      set({
        dashboardStats: stats,
        findings,
        graphData,
        attackPaths,
        riskScores,
        riskSummary,
        recommendations,
        timeline,
        isLoading: false,
      });
    } catch (err) {
      set({ error: err.message, isLoading: false });
    }
  },

  loadScans: async () => {
    try {
      const scans = await api.listScans();
      set({ scans });
      if (scans.length > 0 && !get().currentScan) {
        const latest = scans[0];
        set({ currentScan: latest });
        if (latest.status === 'completed') {
          get().loadAllData(latest.id);
        }
      }
    } catch (err) {
      console.error('Load scans error:', err);
    }
  },

  loadSources: async () => {
    try {
      const sources = await api.getSources();
      set({ sources });
    } catch (err) {
      console.error('Load sources error:', err);
    }
  },

  generateReport: async (scanId) => {
    try {
      const report = await api.generateReport(scanId);
      set({ report });
      return report;
    } catch (err) {
      set({ error: err.message });
    }
  },

  selectScan: (scan) => {
    set({ currentScan: scan });
    if (scan.status === 'completed') {
      get().loadAllData(scan.id);
    }
  },

  reset: () => {
    get().stopPolling();
    set({
      currentScan: null,
      dashboardStats: null,
      findings: [],
      graphData: null,
      attackPaths: [],
      riskScores: [],
      riskSummary: null,
      recommendations: [],
      timeline: [],
      report: null,
      error: null,
    });
  },
}));

export default useScanStore;
