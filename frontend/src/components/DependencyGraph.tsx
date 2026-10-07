import { useEffect, useRef, useState } from 'react';

interface GraphNode {
  data: {
    id: string;
    label: string;
    name?: string;
    version?: string;
    ecosystem?: string;
    severity?: string;
    is_direct?: boolean;
    scope?: string;
  };
}

interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
  };
}

interface DependencyGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings?: any[];
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

export default function DependencyGraph({ nodes, edges, findings = [] }: DependencyGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [layoutName, setLayoutName] = useState<'cose' | 'breadthfirst' | 'concentric'>('cose');

  useEffect(() => {
    if (!containerRef.current || nodes.length === 0) return;

    let cy: any;
    import('cytoscape').then(cytoscapeModule => {
      const cytoscape = cytoscapeModule.default || cytoscapeModule;

      const elements = [
        ...nodes.map(n => {
          const sev = n.data.severity;
          const isRoot = n.data.scope === 'root';
          const bg = sev
            ? SEVERITY_COLORS[sev] || '#ef4444'
            : isRoot
            ? '#8b5cf6'
            : n.data.is_direct
            ? '#3b82f6'
            : '#64748b';

          return {
            group: 'nodes' as const,
            data: {
              ...n.data,
              color: bg,
              borderColor: sev ? '#ffffff' : isRoot ? '#c084fc' : '#1e293b',
              borderWidth: sev ? 2 : isRoot ? 3 : 1.5,
              nodeSize: isRoot ? 40 : 30,
            },
          };
        }),
        ...edges.map(e => ({
          group: 'edges' as const,
          data: e.data,
        })),
      ];

      cy = cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'background-color': 'data(color)',
              color: '#f8fafc',
              'font-size': '11px',
              'font-weight': 'bold',
              'text-valign': 'bottom',
              'text-margin-y': 6,
              'text-background-opacity': 0.7,
              'text-background-color': '#0f172a',
              'text-background-padding': '2px',
              'text-background-shape': 'roundrectangle',
              width: 'data(nodeSize)',
              height: 'data(nodeSize)',
              'border-width': 'data(borderWidth)',
              'border-color': 'data(borderColor)',
            } as any,
          },
          {
            selector: 'edge',
            style: {
              width: 2,
              'line-color': '#475569',
              'target-arrow-color': '#60a5fa',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'arrow-scale': 1.2,
              opacity: 0.8,
            } as any,
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': 4,
              'border-color': '#38bdf8',
              'shadow-blur': 12,
              'shadow-color': '#38bdf8',
              'shadow-opacity': 0.8,
            } as any,
          },
        ],
        layout: {
          name: layoutName,
          animate: true,
          animationDuration: 600,
          padding: 40,
          ...(layoutName === 'cose'
            ? {
                nodeRepulsion: () => 9000,
                idealEdgeLength: () => 90,
                gravity: 0.25,
              }
            : {}),
        } as any,
      });

      // Interactive click node handler
      cy.on('tap', 'node', (evt: any) => {
        const data = evt.target.data();
        setSelectedNode(data);
      });

      cy.on('tap', (evt: any) => {
        if (evt.target === cy) {
          setSelectedNode(null);
        }
      });

      cyRef.current = cy;
    });

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
      }
    };
  }, [nodes, edges, layoutName]);

  // Zoom / Fit handlers
  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 30);

  if (nodes.length === 0) {
    return (
      <div className="card text-center py-12">
        <span className="text-4xl mb-4 block">🕸️</span>
        <p className="text-gray-400">No dependency graph available</p>
        <p className="text-xs text-gray-600 mt-1">Complete a scan to visualize dependencies</p>
      </div>
    );
  }

  // Filter findings matching selected node
  const nodeFindings = selectedNode
    ? findings.filter(
        f =>
          (f.component_purl && f.component_purl === selectedNode.id) ||
          (f.component_name && selectedNode.name && f.component_name.toLowerCase() === selectedNode.name.toLowerCase())
      )
    : [];

  // Outgoing dependencies & Incoming dependents for selected node
  const directChildren = selectedNode
    ? edges.filter(e => e.data.source === selectedNode.id).map(e => e.data.target)
    : [];
  const directParents = selectedNode
    ? edges.filter(e => e.data.target === selectedNode.id).map(e => e.data.source)
    : [];

  return (
    <div className="card p-0 overflow-hidden relative border border-gray-800 shadow-xl">
      {/* Top Header Bar */}
      <div className="px-5 py-3.5 bg-gray-900/80 border-b border-gray-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            🕸️ Dependency Graph
          </h3>
          <span className="text-xs font-mono text-gray-400 bg-gray-800 px-2 py-0.5 rounded border border-gray-700">
            {nodes.length} Nodes · {edges.length} Relationships
          </span>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 text-[11px] flex-wrap">
          <span className="flex items-center gap-1.5 text-purple-300">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500"></span> Root App
          </span>
          <span className="flex items-center gap-1.5 text-blue-300">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span> Direct
          </span>
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-500"></span> Transitive
          </span>
          <span className="flex items-center gap-1.5 text-red-400 font-semibold">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Vulnerable
          </span>
        </div>

        {/* Layout & Zoom Controls */}
        <div className="flex items-center gap-1 bg-gray-800/80 p-1 rounded-lg border border-gray-700">
          <select
            value={layoutName}
            onChange={e => setLayoutName(e.target.value as any)}
            className="bg-transparent text-gray-300 text-xs px-2 py-0.5 outline-none cursor-pointer"
          >
            <option value="cose" className="bg-gray-900">Force-Directed</option>
            <option value="breadthfirst" className="bg-gray-900">Hierarchical Tree</option>
            <option value="concentric" className="bg-gray-900">Concentric</option>
          </select>
          <div className="w-px h-4 bg-gray-700 mx-1" />
          <button
            onClick={handleZoomIn}
            className="px-2 py-0.5 text-xs text-gray-300 hover:text-white hover:bg-gray-700 rounded transition-colors"
            title="Zoom In"
          >
            +
          </button>
          <button
            onClick={handleZoomOut}
            className="px-2 py-0.5 text-xs text-gray-300 hover:text-white hover:bg-gray-700 rounded transition-colors"
            title="Zoom Out"
          >
            -
          </button>
          <button
            onClick={handleFit}
            className="px-2 py-0.5 text-xs text-gray-300 hover:text-white hover:bg-gray-700 rounded transition-colors"
            title="Fit Graph"
          >
            ⛶
          </button>
        </div>
      </div>

      {/* Main Canvas Area */}
      <div className="relative">
        <div ref={containerRef} className="w-full h-[450px] bg-[#0b101b]" />

        {/* Click Node Evidence & Details Drawer */}
        {selectedNode && (
          <div className="absolute top-3 right-3 w-80 sm:w-96 max-h-[420px] overflow-y-auto bg-gray-900/95 border border-gray-700 rounded-xl p-4 shadow-2xl backdrop-blur-md space-y-3 z-10 text-xs">
            <div className="flex items-start justify-between border-b border-gray-800 pb-2">
              <div>
                <span className="text-[10px] uppercase font-bold text-gray-400 tracking-wider block">
                  Component Inspector
                </span>
                <h4 className="text-sm font-bold text-white break-all flex items-center gap-1.5">
                  {selectedNode.name || selectedNode.label}
                  {selectedNode.version && (
                    <span className="text-xs text-blue-400 font-mono">@{selectedNode.version}</span>
                  )}
                </h4>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-gray-400 hover:text-white text-base px-1 leading-none"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div className="bg-gray-800/60 p-2 rounded border border-gray-800">
                <span className="text-gray-500 block">Status</span>
                <span className={`font-semibold ${selectedNode.is_direct ? 'text-blue-400' : 'text-gray-300'}`}>
                  {selectedNode.scope === 'root' ? 'Project Root' : selectedNode.is_direct ? 'Direct Dependency' : 'Transitive Dependency'}
                </span>
              </div>
              <div className="bg-gray-800/60 p-2 rounded border border-gray-800">
                <span className="text-gray-500 block">Ecosystem</span>
                <span className="font-mono text-gray-300 uppercase">{selectedNode.ecosystem || 'N/A'}</span>
              </div>
              <div className="bg-gray-800/60 p-2 rounded border border-gray-800">
                <span className="text-gray-500 block">Dependents (Used By)</span>
                <span className="font-bold text-white">{directParents.length} parent(s)</span>
              </div>
              <div className="bg-gray-800/60 p-2 rounded border border-gray-800">
                <span className="text-gray-500 block">Dependencies (Requires)</span>
                <span className="font-bold text-white">{directChildren.length} child package(s)</span>
              </div>
            </div>

            <div>
              <span className="text-gray-500 block text-[10px]">Package URL (PURL)</span>
              <span className="font-mono text-[10px] text-gray-300 break-all select-all block bg-black/40 p-1.5 rounded mt-0.5 border border-gray-800">
                {selectedNode.id}
              </span>
            </div>

            {/* Vulnerabilities & Evidence Section */}
            {nodeFindings.length > 0 ? (
              <div className="space-y-2 pt-2 border-t border-gray-800">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-red-400 flex items-center gap-1">
                    ⚠️ Vulnerabilities ({nodeFindings.length})
                  </span>
                  <span className="badge bg-red-500/20 text-red-300 border border-red-500/30 text-[10px]">
                    {selectedNode.severity || 'VULNERABLE'}
                  </span>
                </div>

                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {nodeFindings.map((f: any, idx: number) => (
                    <div key={idx} className="bg-red-950/20 border border-red-500/30 rounded-lg p-2.5 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-red-300 font-mono text-[11px]">
                          {f.cve_id || f.title}
                        </span>
                        <span className="text-[10px] font-bold text-red-400">
                          {f.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-gray-300 leading-snug">{f.description || f.title}</p>
                      
                      {/* Evidence */}
                      {f.evidence && (
                        <div className="text-[10px] text-gray-400 bg-black/40 p-1.5 rounded mt-1 space-y-0.5">
                          {f.evidence.cvss_score && <div>CVSS: <b className="text-red-300">{f.evidence.cvss_score}</b></div>}
                          {f.evidence.affected_versions && (
                            <div>Affected: <span className="font-mono text-gray-300">{JSON.stringify(f.evidence.affected_versions)}</span></div>
                          )}
                          {f.evidence.fixed_versions && (
                            <div>Fixed in: <span className="font-mono text-emerald-400">{JSON.stringify(f.evidence.fixed_versions)}</span></div>
                          )}
                        </div>
                      )}

                      {/* Remediation */}
                      {f.remediation?.action && (
                        <div className="text-[10px] text-emerald-300 bg-emerald-950/30 border border-emerald-500/30 p-1.5 rounded mt-1">
                          Fix: <span className="font-semibold">{f.remediation.action}</span>
                          {f.remediation.target_version && ` → ${f.remediation.target_version}`}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-lg p-2.5 text-center text-emerald-400 text-[11px]">
                🛡️ No known vulnerabilities detected for this component.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
