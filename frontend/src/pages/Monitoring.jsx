import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale,
  BarElement, PointElement, LineElement, Filler,
} from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';
import {
  FiActivity, FiPlay, FiSquare, FiAlertTriangle, FiDatabase, FiGlobe,
  FiUser, FiRefreshCw, FiWifi,
} from 'react-icons/fi';
import api from '../services/api';
import {
  Alert, EmptyState, Loader, PageHeader, SeverityBadge, StatCard,
  StatusBadge, formatBytes, formatDate,
} from '../components/ui';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale,
  BarElement, PointElement, LineElement, Filler);

const POLL_INTERVAL_MS = 5000;

export default function Monitoring() {
  const [projects, setProjects] = useState([]);
  const [dashboard, setDashboard] = useState(null);
  const [logs, setLogs] = useState([]);
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [live, setLive] = useState(true);
  const timerRef = useRef(null);

  const refresh = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true);
    try {
      const [projectsRes, dashboardRes, logsRes, threatsRes] = await Promise.all([
        api.get('/monitoring/projects'),
        api.get('/monitoring/dashboard'),
        api.get('/monitoring/logs'),
        api.get('/monitoring/threats'),
      ]);
      setProjects(projectsRes.data.projects || []);
      setDashboard(dashboardRes.data);
      setLogs(logsRes.data.logs || []);
      setThreats(threatsRes.data.threats || []);
    } catch (err) {
      setError(err.response?.data?.error || 'Could not load monitoring data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(true); }, [refresh]);

  useEffect(() => {
    if (!live) {
      clearInterval(timerRef.current);
      return undefined;
    }
    timerRef.current = setInterval(() => refresh(false), POLL_INTERVAL_MS);
    return () => clearInterval(timerRef.current);
  }, [live, refresh]);

  const toggleMonitoring = async (projectId, running) => {
    setBusy(projectId);
    setError('');
    try {
      await api.post(`/monitoring/${running ? 'stop' : 'start'}/${projectId}`);
      await refresh(false);
    } catch (err) {
      setError(err.response?.data?.error || 'The monitoring state could not be changed.');
    } finally {
      setBusy('');
    }
  };

  if (loading) return <Loader label="Loading cloud security monitoring..." />;

  const severity = dashboard?.severity_distribution || {};
  const categories = dashboard?.threat_categories || {};
  const hasSeverity = Object.values(severity).some((v) => v > 0);
  const hasCategories = Object.keys(categories).length > 0;

  const severityChart = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [severity.Critical || 0, severity.High || 0, severity.Medium || 0, severity.Low || 0],
      backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6'],
      borderWidth: 0,
    }],
  };

  const categoryChart = {
    labels: Object.keys(categories),
    datasets: [{
      label: 'Detections',
      data: Object.values(categories),
      backgroundColor: '#06b6d4',
      borderRadius: 6,
    }],
  };

  const countryTally = logs.reduce((acc, log) => {
    if (log.country) acc[log.country] = (acc[log.country] || 0) + 1;
    return acc;
  }, {});
  const topCountries = Object.entries(countryTally).sort((a, b) => b[1] - a[1]).slice(0, 5);

  const userTally = logs.reduce((acc, log) => {
    if (log.username) acc[log.username] = (acc[log.username] || 0) + 1;
    return acc;
  }, {});
  const topUsers = Object.entries(userTally).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cloud Security Monitoring"
        subtitle="Phase 2 · Continuous log collection, AI threat detection, and event correlation"
      >
        <button
          onClick={() => setLive((v) => !v)}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium border transition-colors
            ${live
              ? 'bg-green-500/10 border-green-500/30 text-green-400'
              : 'bg-gray-800 border-gray-700 text-gray-400'}`}
        >
          <FiWifi className={live ? 'animate-pulse' : ''} />
          {live ? 'Live' : 'Paused'}
        </button>
        <button onClick={() => refresh(false)} className="btn-secondary flex items-center gap-2">
          <FiRefreshCw /> Refresh
        </button>
      </PageHeader>

      {error && <Alert type="error">{error}</Alert>}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={FiActivity} label="Monitored Projects" value={dashboard?.active_projects ?? 0}
          color="bg-primary-600" delay={0} hint={`${dashboard?.active_monitoring ?? 0} actively running`} />
        <StatCard icon={FiDatabase} label="Logs Collected" value={dashboard?.total_logs ?? 0}
          color="bg-accent-600" delay={0.05} />
        <StatCard icon={FiAlertTriangle} label="Validated Threats" value={dashboard?.total_threats ?? 0}
          color="bg-danger-600" delay={0.1} />
        <StatCard icon={FiGlobe} label="Source Countries" value={Object.keys(countryTally).length}
          color="bg-warning-600" delay={0.15} />
      </div>

      {projects.length === 0 ? (
        <EmptyState
          icon={FiActivity}
          title="No projects are eligible for monitoring"
          description="A project reaches Phase 2 after Phase 1 approval (score near the threshold with manageable residual critical risk)."
          action={<Link to="/projects" className="btn-primary">Go to Projects</Link>}
        />
      ) : (
        <div className="card">
          <h3 className="font-semibold mb-4">Monitored Projects</h3>
          <div className="space-y-3">
            {projects.map((project) => {
              const running = project.monitoring_state === 'Running';
              return (
                <div key={project.project_id}
                  className="flex items-center justify-between gap-4 flex-wrap p-4 bg-gray-800/40 rounded-lg border border-gray-800">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${running ? 'bg-green-400 animate-pulse' : 'bg-gray-600'}`} />
                    <div className="min-w-0">
                      <Link to={`/projects/${project.project_id}`}
                        className="font-medium text-sm hover:text-primary-400 transition-colors">
                        {project.project_name}
                      </Link>
                      <p className="text-xs text-gray-500">
                        {project.project_id} · {project.total_logs} logs · {project.total_threats} threats
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <StatusBadge status={project.monitoring_state} />
                    <button
                      onClick={() => toggleMonitoring(project.project_id, running)}
                      disabled={busy === project.project_id}
                      className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors
                        ${running
                          ? 'bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25'
                          : 'bg-green-500/15 text-green-400 border border-green-500/30 hover:bg-green-500/25'}
                        disabled:opacity-50`}
                    >
                      {running ? <FiSquare /> : <FiPlay />}
                      {busy === project.project_id ? '...' : running ? 'Stop' : 'Start'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="font-semibold mb-4">Threat Severity Distribution</h3>
          <div className="h-56 flex items-center justify-center">
            {hasSeverity ? (
              <Doughnut data={severityChart} options={{
                maintainAspectRatio: false,
                cutout: '62%',
                plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af', boxWidth: 12, padding: 12 } } },
              }} />
            ) : (
              <p className="text-sm text-gray-500">No threats detected yet. Start monitoring to generate activity.</p>
            )}
          </div>
        </div>

        <div className="card">
          <h3 className="font-semibold mb-4">Attack Categories</h3>
          <div className="h-56">
            {hasCategories ? (
              <Bar data={categoryChart} options={{
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: {
                  x: { ticks: { color: '#6b7280', precision: 0 }, grid: { color: '#1f2937' } },
                  y: { ticks: { color: '#9ca3af' }, grid: { display: false } },
                },
              }} />
            ) : (
              <div className="h-full flex items-center justify-center">
                <p className="text-sm text-gray-500">No attack categories recorded yet.</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="font-semibold mb-4">Top Source Countries</h3>
          {topCountries.length > 0 ? (
            <div className="space-y-3">
              {topCountries.map(([country, count]) => (
                <div key={country}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-gray-300">{country}</span>
                    <span className="text-gray-500">{count}</span>
                  </div>
                  <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <motion.div className="h-full bg-gradient-to-r from-primary-500 to-accent-500"
                      initial={{ width: 0 }}
                      animate={{ width: `${(count / topCountries[0][1]) * 100}%` }}
                      transition={{ duration: 0.5 }} />
                  </div>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-gray-500">No log activity yet.</p>}
        </div>

        <div className="card">
          <h3 className="font-semibold mb-4">Most Active Users</h3>
          {topUsers.length > 0 ? (
            <div className="space-y-2.5">
              {topUsers.map(([user, count]) => (
                <div key={user} className="flex items-center justify-between p-2.5 bg-gray-800/40 rounded-lg">
                  <span className="flex items-center gap-2.5 text-sm">
                    <FiUser className="text-gray-500" /> {user}
                  </span>
                  <span className="text-sm text-gray-500">{count} events</span>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-gray-500">No user activity yet.</p>}
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold">Recent AI Detections</h3>
          <span className="text-xs text-gray-500">
            Validated at 85% confidence or above · lower confidence stays an observation
          </span>
        </div>
        {threats.length === 0 ? (
          <p className="text-sm text-gray-500 py-6 text-center">No detections recorded yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-2 pr-4 font-medium">Time</th>
                  <th className="pb-2 pr-4 font-medium">Project</th>
                  <th className="pb-2 pr-4 font-medium">Threat</th>
                  <th className="pb-2 pr-4 font-medium">Severity</th>
                  <th className="pb-2 pr-4 font-medium">Confidence</th>
                  <th className="pb-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {threats.slice(0, 15).map((threat) => (
                  <tr key={threat.id} className="border-b border-gray-800/60 last:border-0">
                    <td className="py-2.5 pr-4 text-gray-500 whitespace-nowrap">{formatDate(threat.created_date)}</td>
                    <td className="py-2.5 pr-4 text-gray-400">{threat.project_id}</td>
                    <td className="py-2.5 pr-4 text-gray-200">{threat.threat_type}</td>
                    <td className="py-2.5 pr-4"><SeverityBadge severity={threat.severity} /></td>
                    <td className="py-2.5 pr-4 text-gray-300">{threat.confidence}%</td>
                    <td className="py-2.5"><StatusBadge status={threat.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold">Live Cloud Event Stream</h3>
          <span className="text-xs text-gray-500">{logs.length} most recent events</span>
        </div>
        {logs.length === 0 ? (
          <p className="text-sm text-gray-500 py-6 text-center">
            No cloud events yet. Start monitoring on an approved project to begin the simulated event stream.
          </p>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto pr-1 font-mono text-xs">
            {logs.map((log, index) => (
              <div key={log._id || index}
                className={`flex items-start gap-3 p-2.5 rounded-lg border
                  ${log.isSuspicious
                    ? 'bg-red-500/5 border-red-500/20'
                    : 'bg-gray-800/30 border-gray-800'}`}>
                <span className="text-gray-600 shrink-0">{formatDate(log.timestamp)}</span>
                <span className="text-accent-400 shrink-0">{log.eventType}</span>
                <span className="text-gray-400 shrink-0">{log.username}</span>
                <span className="text-gray-500 shrink-0">{log.sourceIP}</span>
                <span className="text-gray-500 shrink-0">{log.country}</span>
                <span className={`shrink-0 ${log.status === 'Failure' ? 'text-red-400' : 'text-green-400'}`}>
                  {log.status}
                </span>
                {log.bytesTransferred > 0 && (
                  <span className="text-yellow-400 shrink-0">{formatBytes(log.bytesTransferred)}</span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
