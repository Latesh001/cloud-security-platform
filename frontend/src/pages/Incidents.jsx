import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';
import {
  FiAlertTriangle, FiCheckCircle, FiClock, FiShield, FiRefreshCw, FiSearch, FiZap,
} from 'react-icons/fi';
import api from '../services/api';
import {
  Alert, EmptyState, Loader, PageHeader, SeverityBadge, StatCard,
  StatusBadge, formatDate,
} from '../components/ui';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement);

const SEVERITIES = ['All', 'Critical', 'High', 'Medium', 'Low'];
const STATUSES = ['All', 'Open', 'In Progress', 'Resolved', 'Closed'];

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');

  const load = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true);
    try {
      const { data } = await api.get('/incidents');
      setIncidents(data.incidents || []);
      setStats(data.stats || null);
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || 'Could not load incidents.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(true); }, [load]);

  if (loading) return <Loader label="Loading incidents..." />;

  const filtered = incidents.filter((incident) => {
    const term = search.toLowerCase();
    const matchesSearch = !term
      || incident.incident_id.toLowerCase().includes(term)
      || incident.threat.toLowerCase().includes(term)
      || incident.project_id.toLowerCase().includes(term)
      || (incident.affected_user || '').toLowerCase().includes(term);
    const matchesSeverity = severityFilter === 'All' || incident.severity === severityFilter;
    const openLike = incident.status === 'Open' || incident.status === 'In Progress';
    const matchesStatus = statusFilter === 'All'
      || (statusFilter === 'Open' && openLike)
      || incident.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const threatTally = incidents.reduce((acc, incident) => {
    acc[incident.threat] = (acc[incident.threat] || 0) + 1;
    return acc;
  }, {});

  const threatChart = {
    labels: Object.keys(threatTally),
    datasets: [{
      label: 'Incidents',
      data: Object.values(threatTally),
      backgroundColor: '#ef4444',
      borderRadius: 6,
    }],
  };

  const resolvedCount = stats?.resolved ?? 0;
  const totalCount = stats?.total ?? 0;
  const actionTotal = stats?.response_actions ?? 0;
  const actionOk = stats?.response_succeeded ?? 0;
  const successRate = actionTotal > 0
    ? (stats?.response_success_rate ?? Math.round((actionOk / actionTotal) * 100))
    : (totalCount > 0 ? Math.round((resolvedCount / totalCount) * 100) : 0);
  const successHint = actionTotal > 0
    ? `${actionOk} of ${actionTotal} playbook actions succeeded`
    : `${resolvedCount} of ${totalCount} handled`;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Incident Response"
        subtitle="Phase 3 · Automated SOAR playbooks, forensic evidence, and incident reporting"
      >
        <button onClick={() => load(false)} className="btn-secondary flex items-center gap-2">
          <FiRefreshCw /> Refresh
        </button>
      </PageHeader>

      {error && <Alert type="error">{error}</Alert>}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={FiAlertTriangle} label="Total Incidents" value={totalCount}
          color="bg-primary-600" delay={0} />
        <StatCard icon={FiZap} label="Critical" value={stats?.critical ?? 0}
          color="bg-danger-600" delay={0.05} />
        <button type="button" className="text-left" onClick={() => setStatusFilter('Open')}>
          <StatCard icon={FiClock} label="Open" value={stats?.open ?? 0}
            color="bg-warning-600" delay={0.1} hint="Click to show open and in-progress cases" />
        </button>
        <StatCard icon={FiCheckCircle} label="Response Success" value={`${successRate}%`}
          color="bg-success-600" delay={0.15} hint={successHint} />
      </div>

      {incidents.length === 0 ? (
        <EmptyState
          icon={FiShield}
          title="No incidents recorded"
          description="Incidents are created automatically when Phase 2 detects a threat at 85% confidence or above. Start monitoring on an approved project to generate activity."
          action={<Link to="/monitoring" className="btn-primary">Go to Monitoring</Link>}
        />
      ) : (
        <>
          {Object.keys(threatTally).length > 0 && (
            <div className="card">
              <h3 className="font-semibold mb-4">Incidents by Threat Category</h3>
              <div className="h-56">
                <Bar data={threatChart} options={{
                  maintainAspectRatio: false,
                  indexAxis: 'y',
                  plugins: { legend: { display: false } },
                  scales: {
                    x: { ticks: { color: '#6b7280', precision: 0 }, grid: { color: '#1f2937' } },
                    y: { ticks: { color: '#9ca3af' }, grid: { display: false } },
                  },
                }} />
              </div>
            </div>
          )}

          <div className="card space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[220px]">
                <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search by incident ID, threat, project, or user..."
                  className="input-field pl-10"
                />
              </div>
            </div>

            <div className="flex flex-wrap gap-4">
              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.map((level) => (
                  <button key={level} onClick={() => setSeverityFilter(level)}
                    className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors
                      ${severityFilter === level ? 'bg-primary-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-gray-200'}`}>
                    {level}
                  </button>
                ))}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {STATUSES.map((status) => (
                  <button key={status} onClick={() => setStatusFilter(status)}
                    className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors
                      ${statusFilter === status ? 'bg-accent-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-gray-200'}`}>
                    {status}
                  </button>
                ))}
              </div>
            </div>

            {filtered.length === 0 ? (
              <p className="text-sm text-gray-500 py-8 text-center">No incidents match the current filters.</p>
            ) : (
              <div className="space-y-2.5">
                {filtered.map((incident, index) => (
                  <motion.div key={incident.incident_id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: Math.min(index * 0.03, 0.4) }}>
                    <Link to={`/incidents/${incident.incident_id}`}
                      className="block p-4 bg-gray-800/40 rounded-lg border border-gray-800 hover:border-primary-500/40 transition-colors group">
                      <div className="flex items-start justify-between gap-4 flex-wrap">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2.5 flex-wrap">
                            <span className="font-mono text-sm text-primary-400 group-hover:text-primary-300">
                              {incident.incident_id}
                            </span>
                            <span className="font-medium text-sm">{incident.threat}</span>
                          </div>
                          <p className="text-xs text-gray-500 mt-1.5">
                            {incident.project_id} · {incident.affected_user || 'unknown user'} ·
                            {' '}{incident.source_ip || 'no IP'} · {formatDate(incident.created_time)}
                          </p>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="text-xs text-gray-500">{incident.confidence}%</span>
                          <SeverityBadge severity={incident.severity} />
                          <StatusBadge status={incident.status} />
                        </div>
                      </div>
                    </Link>
                  </motion.div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
