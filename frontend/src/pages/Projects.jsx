import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { FiPlus, FiFolder, FiSearch } from 'react-icons/fi';
import api from '../services/api';

const statusColors = {
  'Created': 'bg-gray-500/20 text-gray-400',
  'Uploaded': 'bg-blue-500/20 text-blue-400',
  'Scanning': 'bg-yellow-500/20 text-yellow-400',
  'Approved': 'bg-green-500/20 text-green-400',
  'Monitoring Enabled': 'bg-cyan-500/20 text-cyan-400',
  'Pending Remediation': 'bg-orange-500/20 text-orange-400',
  'Incident Detected': 'bg-red-500/20 text-red-400',
};

export default function Projects() {
  const [projects, setProjects] = useState([]);
  const [search, setSearch] = useState('');

  useEffect(() => {
    api.get('/projects').then(r => setProjects(r.data.projects)).catch(console.error);
  }, []);

  const filtered = projects.filter(p =>
    p.project_name.toLowerCase().includes(search.toLowerCase()) ||
    p.project_id.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold">Projects</h1>
          <p className="text-gray-500">Manage your security assessment projects</p>
        </div>
        <Link to="/projects/create" className="btn-primary flex items-center gap-2">
          <FiPlus /> New Project
        </Link>
      </div>

      <div className="relative max-w-md">
        <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search projects..."
          className="input-field pl-10" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.map((p, i) => (
          <motion.div key={p.project_id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}>
            <Link to={`/projects/${p.project_id}`} className="card block hover:border-primary-500/40 transition-all group">
              <div className="flex items-start justify-between mb-3">
                <div className="w-10 h-10 rounded-lg bg-primary-600/20 flex items-center justify-center group-hover:bg-primary-600/30 transition-colors">
                  <FiFolder className="text-primary-400" />
                </div>
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusColors[p.status] || statusColors['Created']}`}>
                  {p.status}
                </span>
              </div>
              <h3 className="font-semibold group-hover:text-primary-400 transition-colors">{p.project_name}</h3>
              <p className="text-sm text-gray-500 mt-1">{p.project_id} • {p.category}</p>
              <div className="flex items-center justify-between mt-4 pt-3 border-t border-gray-800">
                <span className="text-sm">Score: <strong className={p.security_score >= 65 ? 'text-success-500' : 'text-warning-500'}>{p.security_score || '—'}</strong></span>
                {p.monitoring_enabled && <span className="text-xs text-accent-400">Monitoring ON</span>}
              </div>
            </Link>
          </motion.div>
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="card text-center py-12">
          <FiFolder className="text-4xl text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500">No projects yet. Create your first project to start.</p>
          <Link to="/projects/create" className="btn-primary inline-block mt-4">Create Project</Link>
        </div>
      )}
    </div>
  );
}
