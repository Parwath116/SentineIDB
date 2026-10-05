import React, { useEffect, useRef, useState } from 'react';
import { Network } from 'vis-network';
import { apiFetch } from '../api';
import { useTheme } from '../context/ThemeContext';
import { GraphSkeleton } from '../components/Skeleton';
import PipelineViewer from '../components/PipelineViewer';

export default function AttackChains() {
  const { theme } = useTheme();
  const graphContainerRef = useRef(null);
  const networkInstanceRef = useRef(null);

  const [origins, setOrigins] = useState([]);
  const [selectedHost, setSelectedHost] = useState('');
  const [traceData, setTraceData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const [error, setError] = useState(null);
  const [pipelineMeta, setPipelineMeta] = useState(null);

  const isDark = theme === 'dark';

  // Load origins on mount
  useEffect(() => {
    async function loadOrigins() {
      try {
        setLoading(true);
        const res = await apiFetch('/api/chains/origins');
        const list = res.data || [];
        setOrigins(list);
        if (list.length > 0) {
          // Default to first flagged origin (compromised workstation)
          const flagged = list.find((c) => c.flagged) || list[0];
          setSelectedHost(flagged.host);
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    loadOrigins();
  }, []);

  // Fetch graph trace whenever selectedHost changes
  useEffect(() => {
    if (!selectedHost) return;
    async function fetchTrace() {
      try {
        setLoading(true);
        const res = await apiFetch(`/api/chains/trace?host=${encodeURIComponent(selectedHost)}`);
        setTraceData(res.data);
        setPipelineMeta({ pipeline: res.pipeline, collection: res.collection });
        setSelectedNode(res.data?.nodes?.find((n) => n.id === selectedHost) || null);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    fetchTrace();
  }, [selectedHost]);

  // Render vis-network graph
  useEffect(() => {
    if (!traceData || !graphContainerRef.current) return;

    const { nodes: rawNodes, links: rawLinks, origin } = traceData;

    // Subnet color map
    const subnetColors = {
      workstation: { bg: isDark ? '#1e3a8a' : '#dbeafe', border: '#3b82f6', text: isDark ? '#f8fafc' : '#1e3a8a' },
      app: { bg: isDark ? '#78350f' : '#fef3c7', border: '#f59e0b', text: isDark ? '#f8fafc' : '#78350f' },
      db: { bg: isDark ? '#581c87' : '#f3e8ff', border: '#a855f7', text: isDark ? '#f8fafc' : '#581c87' },
      web: { bg: isDark ? '#14532d' : '#dcfce7', border: '#22c55e', text: isDark ? '#f8fafc' : '#14532d' },
    };

    const visNodes = rawNodes.map((n) => {
      const isOrigin = n.id === origin;
      const themeColors = subnetColors[n.subnet] || { bg: '#64748b', border: '#94a3b8', text: '#ffffff' };
      return {
        id: n.id,
        label: `${n.id}\n(${n.subnet || 'host'})`,
        shape: isOrigin ? 'diamond' : 'box',
        size: isOrigin ? 32 : 24,
        margin: 10,
        color: {
          background: isOrigin ? (isDark ? '#991b1b' : '#fee2e2') : themeColors.bg,
          border: isOrigin ? '#ef4444' : themeColors.border,
          highlight: {
            background: isDark ? '#3b82f6' : '#93c5fd',
            border: '#2563eb',
          },
          hover: {
            background: isDark ? '#2563eb' : '#bfdbfe',
            border: '#1d4ed8',
          },
        },
        font: {
          color: isOrigin ? (isDark ? '#fecaca' : '#991b1b') : themeColors.text,
          face: 'JetBrains Mono, monospace',
          size: 12,
          multi: true,
          bold: isOrigin,
        },
        borderWidth: isOrigin ? 3 : 2,
        shadow: {
          enabled: true,
          color: isDark ? 'rgba(0,0,0,0.6)' : 'rgba(0,0,0,0.1)',
          size: 6,
          x: 2,
          y: 2,
        },
      };
    });

    const visEdges = rawLinks.map((l, idx) => ({
      id: `edge-${idx}`,
      from: l.source,
      to: l.target,
      label: `${l.protocol.toUpperCase()} (Hop ${l.hop})`,
      arrows: 'to',
      font: {
        align: 'middle',
        face: 'JetBrains Mono, monospace',
        size: 11,
        color: isDark ? '#94a3b8' : '#475569',
        background: isDark ? '#0f172a' : '#ffffff',
      },
      color: {
        color: isDark ? '#475569' : '#94a3b8',
        highlight: '#3b82f6',
        hover: '#3b82f6',
      },
      width: 2,
      smooth: { type: 'cubicBezier', roundness: 0.2 },
    }));

    const data = { nodes: visNodes, edges: visEdges };
    const options = {
      physics: {
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -70,
          centralGravity: 0.015,
          springLength: 140,
          springConstant: 0.08,
        },
        stabilization: { iterations: 150 },
      },
      interaction: {
        hover: true,
        tooltipDelay: 100,
        zoomView: true,
        dragView: true,
      },
    };

    if (networkInstanceRef.current) {
      networkInstanceRef.current.destroy();
    }

    const net = new Network(graphContainerRef.current, data, options);
    networkInstanceRef.current = net;

    // Node click selection
    net.on('selectNode', (params) => {
      const nodeId = params.nodes[0];
      const match = rawNodes.find((n) => n.id === nodeId);
      if (match) setSelectedNode(match);
    });

    // Hover effect: highlight neighbors
    net.on('hoverNode', (params) => {
      const hoveredId = params.node;
      const connectedNodes = net.getConnectedNodes(hoveredId);
      const allToHighlight = [hoveredId, ...connectedNodes];

      // Update node styles for neighbor glow
      const updateArray = visNodes.map((n) => ({
        id: n.id,
        opacity: allToHighlight.includes(n.id) ? 1.0 : 0.25,
      }));
      net.body.data.nodes.update(updateArray);
    });

    net.on('blurNode', () => {
      const resetArray = visNodes.map((n) => ({
        id: n.id,
        opacity: 1.0,
      }));
      net.body.data.nodes.update(resetArray);
    });

    return () => {
      if (networkInstanceRef.current) {
        networkInstanceRef.current.destroy();
        networkInstanceRef.current = null;
      }
    };
  }, [traceData, isDark]);

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '24px 20px', minHeight: 'calc(100vh - 120px)' }}>
      {/* Title */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
            Attack Chain Explorer ($graphLookup)
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Graph reconstruction of multi-hop lateral movement traversals across internal infrastructure
          </p>
        </div>

        {/* Origin Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Attack Origin:
          </label>
          <select
            value={selectedHost}
            onChange={(e) => setSelectedHost(e.target.value)}
            style={{
              padding: '7px 12px',
              borderRadius: '6px',
              border: '1px solid var(--border)',
              backgroundColor: 'var(--bg-surface-raised)',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: '13px',
              fontWeight: 600,
            }}
          >
            {origins.map((o) => (
              <option key={o.host} value={o.host}>
                {o.host} ({o.hops} hops{o.flagged ? ' - ATTACK CHAIN' : ''})
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div role="alert" style={{ padding: '12px', borderRadius: '6px', backgroundColor: 'var(--danger-bg)', color: 'var(--danger)', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {/* Main Graph & Detail Split Panel */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 340px', gap: '20px', marginBottom: '20px' }}>
        {/* Graph Canvas */}
        <div className="sdb-card" style={{ position: 'relative', overflow: 'hidden' }}>
          <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Topology Graph for {selectedHost}
              </span>
              {traceData?.hops > 0 && (
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '12px',
                    backgroundColor: 'var(--critical-bg)',
                    color: 'var(--critical)',
                    border: '1px solid var(--critical-border)',
                  }}
                >
                  {traceData.hops} Lateral Hops Detected
                </span>
              )}
            </div>

            <div style={{ display: 'flex', gap: '12px', fontSize: '11px', color: 'var(--text-muted)' }}>
              <span>Scroll to zoom</span>
              <span>•</span>
              <span>Drag to pan</span>
              <span>•</span>
              <span>Hover node to isolate chain</span>
            </div>
          </div>

          {loading ? (
            <GraphSkeleton />
          ) : (
            <div
              ref={graphContainerRef}
              style={{
                width: '100%',
                height: '520px',
                backgroundColor: isDark ? '#0b0f19' : '#f8fafc',
              }}
            />
          )}
        </div>

        {/* Node Detail Drawer / Card */}
        <div className="sdb-card" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <h2 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '12px' }}>
            Asset Inspection
          </h2>

          {selectedNode ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Hostname</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '15px', fontWeight: 700, color: 'var(--accent)' }}>
                  {selectedNode.id}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Subnet Role</span>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                  {selectedNode.subnet || 'Unknown'} Segment
                </div>
              </div>

              <div>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Internal IP</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-primary)' }}>
                  {selectedNode.ip || 'DHCP Pool'}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Criticality</span>
                <span
                  style={{
                    display: 'inline-block',
                    marginTop: '2px',
                    fontSize: '11px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    backgroundColor: selectedNode.criticality === 'critical' ? 'var(--critical-bg)' : 'var(--info-bg)',
                    color: selectedNode.criticality === 'critical' ? 'var(--critical)' : 'var(--info)',
                  }}
                >
                  {selectedNode.criticality || 'Normal'}
                </span>
              </div>

              <div>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Chain Hop Depth</span>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {selectedNode.origin ? '0 (Initial Compromise)' : `Hop ${selectedNode.hop}`}
                </div>
              </div>

              <div style={{ marginTop: '16px', borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
                <a
                  href={`/search?q=${selectedNode.id}`}
                  style={{
                    display: 'block',
                    textAlign: 'center',
                    padding: '8px',
                    borderRadius: '6px',
                    backgroundColor: 'var(--bg-surface-raised)',
                    border: '1px solid var(--border)',
                    fontSize: '12px',
                    fontWeight: 500,
                  }}
                >
                  Inspect Endpoint Logs &rarr;
                </a>
              </div>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '13px', textAlign: 'center', marginTop: '40px' }}>
              Click any node in the attack graph to inspect its asset properties and containment actions.
            </div>
          )}
        </div>
      </div>

      {/* Query Explorer */}
      {pipelineMeta && (
        <PipelineViewer
          collection={pipelineMeta.collection}
          pipeline={pipelineMeta.pipeline}
          description="Pipeline 5 ($graphLookup): traverses connections edge collection recursively matching connectFromField (dstHost) to connectToField (srcHost) restricted to admin protocols (SSH, RDP, SMB, WinRM)."
        />
      )}
    </div>
  );
}
