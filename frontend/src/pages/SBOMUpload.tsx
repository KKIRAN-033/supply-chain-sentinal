import { useEffect, useState, useRef, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';

/**
 * Pure client-side format detector.
 * Deterministically inspects structure and schemas without hardcoded assumptions.
 */
function detectClientFormat(raw: string): string {
  if (!raw || !raw.trim()) return 'auto';
  const text = raw.trim();

  // 1. JSON Schemas (CycloneDX, SPDX, package-lock, package.json)
  if (text.startsWith('{') || (text.startsWith('[') && !text.startsWith('[['))) {
    try {
      const data = JSON.parse(text);
      if (typeof data === 'object' && data !== null) {
        // CycloneDX
        const bomFormat = String(data.bomFormat || '').toLowerCase();
        const schema = String(data.$schema || '').toLowerCase();
        if (
          bomFormat === 'cyclonedx' ||
          schema.includes('cyclonedx') ||
          (data.specVersion && (data.components || data.dependencies))
        ) {
          return 'cyclonedx';
        }

        // SPDX
        if (
          data.spdxVersion ||
          data.SPDXID ||
          schema.includes('spdx') ||
          (data.packages && (data.dataLicense || data.spdxVersion))
        ) {
          return 'spdx';
        }

        // package-lock.json
        if (data.lockfileVersion !== undefined) {
          return 'package_lock';
        }

        // package.json
        if (
          data.dependencies ||
          data.devDependencies ||
          data.peerDependencies ||
          data.optionalDependencies ||
          (data.name && (data.version || data.scripts || data.description || data.main || data.author || data.license || data.private))
        ) {
          return 'package_json';
        }
      }
    } catch {
      // Incomplete or streaming JSON: apply heuristic keywords
      if (text.includes('"bomFormat"') || text.toLowerCase().includes('cyclonedx')) return 'cyclonedx';
      if (text.includes('"spdxVersion"') || text.includes('SPDXID') || text.toLowerCase().includes('spdx')) return 'spdx';
      if (text.includes('"lockfileVersion"')) return 'package_lock';
      if (text.includes('"dependencies"') || text.includes('"devDependencies"')) return 'package_json';
    }
    return 'auto'; // Never fall through to requirements.txt if content starts with JSON bracket
  }

  // 2. Python Poetry lockfile (TOML table [[package]])
  if (text.includes('[[package]]') && (text.includes('name =') || text.includes('version ='))) {
    return 'poetry_lock';
  }

  // 3. Python requirements.txt
  const lines = text
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#') && !l.startsWith('-r') && !l.startsWith('-i') && !l.startsWith('--'));

  if (lines.length > 0) {
    const reqPattern = /^[a-zA-Z0-9][a-zA-Z0-9._\-\[\]]*(\s*([><=!~^@]=?\s*[\w\.\*\+\-\_\/\:]+(\s*,\s*[><=!~^]=?\s*[\w\.\*\+\-\_\/\:]+)*)?(\s*;.*)?)?$/;
    const matchCount = lines.filter(l => reqPattern.test(l)).length;
    if (matchCount / lines.length >= 0.4) {
      return 'requirements_txt';
    }
  }

  return 'auto';
}

export default function SBOMUpload() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProject, setSelectedProject] = useState('');
  const [inputType, setInputType] = useState('auto');
  const [content, setContent] = useState('');
  const [fileName, setFileName] = useState('');
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');

  // Project manifests state (loaded dynamically from repository)
  const [manifests, setManifests] = useState<{ name: string; path: string; format: string; download_url: string }[]>([]);
  const [selectedManifestPath, setSelectedManifestPath] = useState('');
  const [isLoadingManifests, setIsLoadingManifests] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Format label mapping
  const formatLabel: Record<string, string> = {
    package_json: 'npm (package.json)',
    package_lock: 'Lockfile (package-lock / yarn.lock)',
    requirements_txt: 'Python (requirements.txt)',
    poetry_lock: 'Python Poetry (poetry.lock)',
    cyclonedx: 'CycloneDX JSON',
    spdx: 'SPDX JSON',
    auto: 'Auto-detect',
  };

  // Real-time auto-detected format from content
  const detectedFormat = useMemo(() => {
    return detectClientFormat(content);
  }, [content]);

  useEffect(() => {
    api.listProjects().then(data => {
      setProjects(data || []);
      if (data && data.length > 0) {
        const queryProj = searchParams.get('project');
        const savedProj = localStorage.getItem('sentinel_active_project');
        const preferred = (queryProj && data.find(p => p.id === queryProj))
          || (savedProj && data.find(p => p.id === savedProj))
          || data[0];
        const initialId = preferred.id;
        setSelectedProject(initialId);
        localStorage.setItem('sentinel_active_project', initialId);
        loadManifestsForProject(initialId);
      }
    }).catch(() => {});
  }, [searchParams]);

  const loadManifestsForProject = async (projectId: string) => {
    if (!projectId) {
      setManifests([]);
      setSelectedManifestPath('');
      return;
    }

    setIsLoadingManifests(true);
    setSelectedManifestPath('');

    try {
      const res = await api.getProjectManifests(projectId);
      setManifests(res.manifests || []);
      // We deliberately do NOT force-populate content so user can paste or choose freely
    } catch {
      setManifests([]);
    } finally {
      setIsLoadingManifests(false);
    }
  };

  const loadManifestContent = async (manifest: { name: string; path: string; format: string; download_url: string }, projId?: string) => {
    const currentProj = projId || selectedProject;
    setError('');
    setSelectedManifestPath(manifest.path);
    setFileName(manifest.path);
    setInputType('auto'); // Auto-detect loaded content

    try {
      const res = await api.getProjectManifestContent(currentProj, manifest.path);
      if (res && res.content) {
        setContent(res.content);
        if (fileInputRef.current) fileInputRef.current.value = '';
        return;
      }
    } catch {
      // Fallback: direct download if url provided
    }

    if (manifest.download_url) {
      try {
        const resp = await fetch(manifest.download_url);
        if (resp.ok) {
          const text = await resp.text();
          setContent(text);
          if (fileInputRef.current) fileInputRef.current.value = '';
          return;
        }
      } catch {}
    }

    setError(`Failed to load content for ${manifest.path}`);
  };

  const handleProjectChange = (projectId: string) => {
    setSelectedProject(projectId);
    localStorage.setItem('sentinel_active_project', projectId);
    window.dispatchEvent(new Event('storage'));
    window.dispatchEvent(new CustomEvent('sentinel:project-change', { detail: projectId }));
    setContent('');
    setFileName('');
    setSelectedManifestPath('');
    setInputType('auto');
    setManifests([]);
    loadManifestsForProject(projectId);
  };

  // Format dropdown change: handles repo manifest selection or format override
  const handleFormatChange = async (val: string) => {
    if (!val) return;

    if (val.startsWith('repo:')) {
      const manifestPath = val.replace('repo:', '');
      const manifest = manifests.find(m => m.path === manifestPath);
      if (manifest) {
        await loadManifestContent(manifest);
        return;
      }
    }

    // Standard format (auto, package_json, requirements_txt, etc.)
    setSelectedManifestPath('');
    setInputType(val);
  };

  // File upload from local computer
  const handleFileUpload = async (file: File) => {
    if (!file) return;
    try {
      const text = await file.text();
      setContent(text);
      setFileName(file.name);
      setSelectedManifestPath('');
      setInputType('auto'); // Trigger pure auto-detection on the file content
      setError('');
    } catch {
      setError('Failed to read file content');
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleClear = () => {
    setContent('');
    setFileName('');
    setInputType('auto');
    setSelectedManifestPath('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSubmit = async () => {
    if (!selectedProject) {
      setError('Please select a project before scanning');
      return;
    }
    const finalContent = content.trim();
    if (!finalContent) {
      setError('Validation error: Please paste manifest content or upload an SBOM before scanning.');
      return;
    }

    setError('');
    setUploading(true);

    try {
      // Dynamic format resolution: if auto, use client-detected format or let backend detect
      const effectiveInputType = inputType === 'auto'
        ? (detectedFormat !== 'auto' ? detectedFormat : 'auto')
        : inputType;

      const result = await api.createScan(selectedProject, {
        input_type: effectiveInputType,
        raw_content: finalContent,
      });
      localStorage.setItem('sentinel_active_project', selectedProject);
      window.dispatchEvent(new Event('storage'));
      window.dispatchEvent(new CustomEvent('sentinel:project-change', { detail: selectedProject }));
      navigate(`/scan/${result.scan_id}`);
    } catch (e: any) {
      setError(e.message || 'Scan creation failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Upload SBOM / Manifest</h1>
        <p className="text-sm text-gray-400 mt-1">
          Scan repository manifests or upload an SBOM file to detect supply chain risks
        </p>
      </div>

      <div className="card space-y-5">
        {/* Row 1: Target Project + Format Dropdown */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-gray-400 uppercase tracking-wider block mb-1.5 font-semibold">
              Target Project <span className="text-red-400">*</span>
            </label>
            <select
              value={selectedProject}
              onChange={e => handleProjectChange(e.target.value)}
              className="input-field"
            >
              <option value="">Select project...</option>
              {projects.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name} {p.environment ? `(${p.environment})` : ''}
                </option>
              ))}
            </select>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs text-gray-400 uppercase tracking-wider font-semibold">
                Format / Manifest File <span className="text-red-400">*</span>
              </label>
              {isLoadingManifests && (
                <span className="text-xs text-blue-400 flex items-center gap-1.5">
                  <div className="animate-spin w-3 h-3 border-2 border-blue-400 border-t-transparent rounded-full" />
                  Checking repository...
                </span>
              )}
            </div>
            <select
              value={selectedManifestPath ? `repo:${selectedManifestPath}` : inputType}
              onChange={e => handleFormatChange(e.target.value)}
              className="input-field"
              disabled={isLoadingManifests}
            >
              <option value="auto">
                ⚡ Auto-detect {detectedFormat && detectedFormat !== 'auto' ? `(Detected: ${formatLabel[detectedFormat] || detectedFormat})` : ''}
              </option>
              <optgroup label="Standard Formats (Manual Override)">
                <option value="package_json">npm (package.json)</option>
                <option value="package_lock">Lockfile (package-lock / yarn.lock)</option>
                <option value="requirements_txt">Python (requirements.txt)</option>
                <option value="poetry_lock">Python Poetry (poetry.lock)</option>
                <option value="cyclonedx">CycloneDX JSON</option>
                <option value="spdx">SPDX JSON</option>
              </optgroup>

              {manifests.length > 0 && (
                <optgroup label="Repository Manifest Files (Click to load)">
                  {manifests.map(m => (
                    <option key={m.path} value={`repo:${m.path}`}>
                      📄 {m.name || m.path} ({formatLabel[m.format] || m.format})
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
          </div>
        </div>

        {/* Optional Upload / Drag-and-Drop Area */}
        <div
          className="border-2 border-dashed border-gray-700 hover:border-blue-500 rounded-lg p-4 text-center cursor-pointer transition-colors bg-gray-900/30"
          onDragOver={e => e.preventDefault()}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
            accept=".json,.txt,.lock,.toml,.yaml,.yml"
          />
          <p className="text-xs text-gray-400">
            📁 Or upload a local SBOM / manifest file from your computer (auto-detected on upload)
          </p>
        </div>

        {/* Textarea: Content automatically appears here or paste custom content */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="text-xs text-gray-400 uppercase tracking-wider font-semibold">
              {fileName ? `📄 ${fileName}` : 'Manifest / SBOM Content'}
            </label>
            {content && (
              <span className="text-xs font-mono text-gray-400 flex items-center gap-2">
                <span>{content.length.toLocaleString()} characters · {content.split('\n').length} lines</span>
                <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-semibold text-[11px]">
                  {inputType === 'auto'
                    ? (detectedFormat !== 'auto' ? `✨ Auto-detected: ${formatLabel[detectedFormat] || detectedFormat}` : '⚡ Auto-detecting...')
                    : `📌 Selected: ${formatLabel[inputType] || inputType}`}
                </span>
              </span>
            )}
          </div>
          <textarea
            value={content}
            onChange={e => {
              const val = e.target.value;
              setContent(val);
              // Clear bound file and ensure auto-detect is always active on manual paste/edit
              setSelectedManifestPath('');
              setFileName('');
              setInputType('auto');
              if (fileInputRef.current) fileInputRef.current.value = '';
            }}
            className="input-field font-mono text-xs h-64 resize-y"
            placeholder="Paste any package.json, requirements.txt, poetry.lock, or CycloneDX/SPDX SBOM here..."
          />
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-sm text-red-400 flex items-center gap-2">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {/* Submit Actions */}
        <div className="flex justify-end gap-3 pt-2">
          <button type="button" onClick={handleClear} className="btn-secondary">
            Clear
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={uploading || !selectedProject || !content.trim()}
            className="btn-primary"
          >
            {uploading ? (
              <span className="flex items-center gap-2">
                <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full" />
                Scanning...
              </span>
            ) : (
              '🔍 Start Scan'
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
