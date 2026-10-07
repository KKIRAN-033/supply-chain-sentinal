import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';

export default function Projects() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', repo_url: '', environment: 'production', criticality: 'medium' });
  const [creating, setCreating] = useState(false);

  const load = () => {
    api.listProjects().then(setProjects).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async () => {
    if (!form.name.trim()) return;
    setCreating(true);
    try {
      const project = await api.createProject(form);
      setShowCreate(false);
      setForm({ name: '', repo_url: '', environment: 'production', criticality: 'medium' });
      if (project?.id) {
        localStorage.setItem('sentinel_active_project', project.id);
        window.dispatchEvent(new Event('storage'));
        window.dispatchEvent(new CustomEvent('sentinel:project-change', { detail: project.id }));
      }
      load();
    } catch (e) {
      alert('Failed to create project');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Projects</h1>
          <p className="text-sm text-gray-500 mt-1">Manage your monitored repositories</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-primary">+ New Project</button>
      </div>

      {/* Create modal */}
      {showCreate && (
        <div className="card border-sentinel-accent/30 space-y-4">
          <h3 className="text-white font-semibold">Create Project</h3>
          <div className="grid grid-cols-2 gap-4">
            <input
              placeholder="Project name"
              value={form.name}
              onChange={e => setForm({ ...form, name: e.target.value })}
              className="input-field"
            />
            <input
              placeholder="Repository URL (optional)"
              value={form.repo_url}
              onChange={e => setForm({ ...form, repo_url: e.target.value })}
              className="input-field"
            />
            <select
              value={form.environment}
              onChange={e => setForm({ ...form, environment: e.target.value })}
              className="input-field"
            >
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
            </select>
            <select
              value={form.criticality}
              onChange={e => setForm({ ...form, criticality: e.target.value })}
              className="input-field"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div className="flex gap-3 justify-end">
            <button onClick={() => setShowCreate(false)} className="btn-secondary">Cancel</button>
            <button onClick={handleCreate} disabled={creating || !form.name.trim()} className="btn-primary">
              {creating ? 'Creating...' : 'Create Project'}
            </button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
        </div>
      ) : projects.length === 0 ? (
        <div className="card text-center py-12">
          <span className="text-4xl mb-4 block">📁</span>
          <p className="text-gray-400">No projects yet</p>
          <button onClick={() => setShowCreate(true)} className="btn-primary mt-4">Create your first project</button>
        </div>
      ) : (
        <div className="space-y-3">
          {projects.map(p => (
            <div
              key={p.id}
              onClick={() => navigate(`/projects/${p.id}`)}
              className="card cursor-pointer flex items-center justify-between"
            >
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-gradient-to-br from-blue-600/30 to-cyan-500/10 rounded-xl flex items-center justify-center text-xl font-bold text-sentinel-accent">
                  {p.name.charAt(0)}
                </div>
                <div>
                  <h3 className="text-white font-semibold">{p.name}</h3>
                  <div className="flex gap-3 text-xs text-gray-500 mt-0.5">
                    <span>📌 {p.environment}</span>
                    <span>⚡ {p.criticality}</span>
                    {p.repo_url && <span className="text-blue-400/60">🔗 {p.repo_url}</span>}
                  </div>
                </div>
              </div>
              <span className="text-gray-600 text-sm">→</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
