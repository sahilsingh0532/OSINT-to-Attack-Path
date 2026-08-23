import { useState, useCallback, useRef, useEffect } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import useScanStore from '../stores/scanStore';
import { getNodeColor, getNodeShape, capitalize, formatConfidence } from '../utils/helpers';
import { ZoomIn, ZoomOut, Maximize2, X } from 'lucide-react';

export default function AttackSurface() {
  const { graphData } = useScanStore();
  const [selectedNode, setSelectedNode] = useState(null);
  const cyRef = useRef(null);

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="animate-fade-in">
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: '0 0 0.5rem' }}>Attack Surface Map</h1>
        <p style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem' }}>
          Run a scan to generate the attack surface graph.
        </p>
      </div>
    );
  }

  // Convert to Cytoscape elements
  const elements = [
    ...graphData.nodes.map(n => ({
      data: {
        id: n.id,
        label: n.label,
        nodeType: n.node_type,
        confidence: n.confidence,
        observationType: n.observation_type,
        riskLevel: n.risk_level,
        ...n.data,
      },
    })),
    ...graphData.edges.map(e => ({
      data: {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        relationshipType: e.relationship_type,
      },
    })),
  ];

  const stylesheet = [
    {
      selector: 'node',
      style: {
        label: 'data(label)',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'font-size': '9px',
        'font-family': 'Inter, sans-serif',
        color: '#94a3b8',
        'text-wrap': 'ellipsis',
        'text-max-width': '100px',
        'background-opacity': 0.9,
        'border-width': 2,
        'border-opacity': 0.6,
        width: 36,
        height: 36,
        'overlay-opacity': 0,
      },
    },
    // Dynamic node styles by type
    ...['organization', 'domain', 'subdomain', 'ip', 'asn', 'certificate', 'technology',
        'repository', 'identity', 'exposure', 'threat_indicator', 'darkweb_reference'].map(type => ({
      selector: `node[nodeType = "${type}"]`,
      style: {
        'background-color': getNodeColor(type),
        'border-color': getNodeColor(type),
        shape: getNodeShape(type),
      },
    })),
    {
      selector: 'node:selected',
      style: {
        'border-width': 4,
        'border-color': '#00d4ff',
        'background-opacity': 1,
        'text-outline-color': '#0a0e1a',
        'text-outline-width': 2,
        color: '#e2e8f0',
        'font-weight': 'bold',
      },
    },
    {
      selector: 'edge',
      style: {
        width: 1.5,
        'line-color': '#2a3150',
        'target-arrow-color': '#2a3150',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'arrow-scale': 0.8,
        opacity: 0.6,
      },
    },
    {
      selector: 'edge:selected',
      style: {
        'line-color': '#00d4ff',
        'target-arrow-color': '#00d4ff',
        width: 2.5,
        opacity: 1,
      },
    },
  ];

  const handleNodeClick = (evt) => {
    const node = evt.target;
    setSelectedNode(node.data());
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', gap: '1rem', height: 'calc(100vh - 160px)' }}>
      {/* Graph */}
      <div style={{ flex: 1, position: 'relative' }} className="graph-container">
        {/* Controls */}
        <div style={{ position: 'absolute', top: 12, right: 12, zIndex: 10, display: 'flex', gap: '0.25rem' }}>
          <button className="btn-secondary" style={{ padding: '0.375rem' }} onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.2)}>
            <ZoomIn size={14} />
          </button>
          <button className="btn-secondary" style={{ padding: '0.375rem' }} onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 0.8)}>
            <ZoomOut size={14} />
          </button>
          <button className="btn-secondary" style={{ padding: '0.375rem' }} onClick={() => cyRef.current?.fit(undefined, 50)}>
            <Maximize2 size={14} />
          </button>
        </div>

        {/* Title */}
        <div style={{ position: 'absolute', top: 12, left: 12, zIndex: 10 }}>
          <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>Attack Surface Map</h2>
          <p style={{ margin: '0.125rem 0 0', fontSize: '0.6875rem', color: 'var(--color-text-muted)' }}>
            {graphData.nodes.length} nodes · {graphData.edges.length} relationships
          </p>
        </div>

        {/* Legend */}
        <div style={{ position: 'absolute', bottom: 12, left: 12, zIndex: 10, display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
          {['domain', 'subdomain', 'certificate', 'ip', 'technology', 'repository', 'identity', 'exposure', 'threat_indicator'].map(type => (
            <div key={type} style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.625rem', color: 'var(--color-text-muted)', background: 'rgba(10, 14, 26, 0.8)', padding: '0.125rem 0.375rem', borderRadius: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: getNodeColor(type), display: 'inline-block' }} />
              {capitalize(type)}
            </div>
          ))}
        </div>

        <CytoscapeComponent
          elements={elements}
          stylesheet={stylesheet}
          style={{ width: '100%', height: '100%' }}
          layout={{ name: 'cose', animate: true, animationDuration: 500, nodeRepulsion: 8000, idealEdgeLength: 120, gravity: 0.3 }}
          cy={(cy) => {
            cyRef.current = cy;
            cy.on('tap', 'node', handleNodeClick);
          }}
        />
      </div>

      {/* Detail Panel */}
      {selectedNode && (
        <div style={{
          width: 360,
          background: 'var(--color-bg-card)',
          border: '1px solid var(--color-border)',
          borderRadius: 12,
          padding: '1.25rem',
          overflowY: 'auto',
        }} className="animate-slide-in">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
            <div>
              <span style={{
                display: 'inline-block', padding: '0.125rem 0.5rem', borderRadius: 9999, fontSize: '0.625rem', fontWeight: 600,
                background: `${getNodeColor(selectedNode.nodeType)}22`, color: getNodeColor(selectedNode.nodeType),
                marginBottom: '0.5rem',
              }}>
                {capitalize(selectedNode.nodeType)}
              </span>
              <h3 style={{ margin: 0, fontSize: '0.9375rem', fontWeight: 600 }}>{selectedNode.label}</h3>
            </div>
            <button onClick={() => setSelectedNode(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-muted)' }}>
              <X size={16} />
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {selectedNode.value && (
              <div>
                <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.25rem' }}>Value</div>
                <div style={{ fontSize: '0.8125rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{selectedNode.value}</div>
              </div>
            )}
            {selectedNode.source && (
              <div>
                <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.25rem' }}>Source</div>
                <div style={{ fontSize: '0.8125rem' }}>{selectedNode.source}</div>
              </div>
            )}
            {selectedNode.evidence && (
              <div>
                <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.25rem' }}>Evidence</div>
                <div style={{ fontSize: '0.8125rem', color: 'var(--color-text-secondary)' }}>{selectedNode.evidence}</div>
              </div>
            )}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              <div style={{ textAlign: 'center', padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Confidence</div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{formatConfidence(selectedNode.confidence)}</div>
              </div>
              <div style={{ textAlign: 'center', padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Observation</div>
                <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>{capitalize(selectedNode.observationType)}</div>
              </div>
            </div>
            {selectedNode.riskLevel && (
              <div style={{ textAlign: 'center', padding: '0.5rem', background: 'var(--color-bg-secondary)', borderRadius: 8 }}>
                <div style={{ fontSize: '0.625rem', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Risk Level</div>
                <div style={{ fontSize: '0.875rem', fontWeight: 700, color: selectedNode.riskLevel === 'CRITICAL' ? '#dc2626' : selectedNode.riskLevel === 'VERY HIGH' ? '#ea580c' : '#f59e0b' }}>
                  {selectedNode.riskLevel}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
