import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  FiFolder, FiCheckCircle, FiClock, FiActivity, FiAlertTriangle, FiShield, FiTrendingUp,
  FiLayers, FiTarget, FiList, FiCpu,
} from 'react-icons/fi';
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale,
  BarElement, PointElement, LineElement, Filler,
} from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

ChartJS.register(
  ArcElement, Tooltip, Legend, CategoryScale, LinearScale,
  BarElement, PointElement, LineElement, Filler,
);

const StatCard = ({ icon: Icon, label, value, color, delay, suffix = '' }) => (
  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay }}
    className="stat-card">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-gray-500 text-sm">{label}</p>
        <p className="text-3xl font-bold mt-1">{value}{suffix}</p>
      </div>
      <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${color}`}>
        <Icon className="text-xl text-white" />
      </div>
    </div>
  </motion.div>
);

const doughnutOpts = {
  responsive: true,
  maintainAspectRatio: false,
  cutout: '62%',
  plugins: {
    legend: {
      position: 'bottom',
      labels: { color: '#9ca3af', boxWidth: 12, padding: 12 },
    },
  },
};
const barOpts = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  scales: {
    y: { ticks: { color: '#9ca3af', precision: 0 }, grid: { color: '#1f2937' }, beginAtZero: true },
    x: { ticks: { color: '#9ca3af' }, grid: { display: false } },
  },
};

const STATUS_COLORS = {
  Approved: '#22c55e',
  'Monitoring Enabled': '#06b6d4',
  'Pending Remediation': '#f59e0b',
  Pending: '#f59e0b',
  Scanning: '#eab308',
  Created: '#6b7280',
  Uploaded: '#3b82f6',
  'Incident Detected': '#ef4444',
  Incidents: '#ef4444',
  'Upload Failed': '#dc2626',
  Rejected: '#f43f5e',
  Failed: '#ef4444',
  Other: '#6366f1',
};

function chartTotal(dataset) {
  return (dataset || []).reduce((sum, value) => sum + (Number(value) || 0), 0);
}

function DoughnutChart({ data, cutout = '62%' }) {
  const total = chartTotal(data?.datasets?.[0]?.data);
  if (!total) {
    return (
      <div className="h-full w-full flex items-center justify-center">
        <p className="text-sm text-gray-500">No data yet</p>
      </div>
    );
  }
  return (
    <div className="h-full w-full">
      <Doughnut data={data} options={{ ...doughnutOpts, cutout }} />
    </div>
  );
}

function displayProjectStatus(project) {
  const status = project?.status || 'Created';
  const score = Number(project?.security_score) || 0;
  if (status === 'Incident Detected') return 'Incident Detected';
  if (status === 'Approved' || status === 'Monitoring Enabled') return 'Approved';
  const blocked = ['Pending Remediation', 'Upload Failed', 'Rejected', 'Scanning', 'Created', 'Uploaded'];
  if (score >= 65 && !blocked.includes(status)) return 'Approved';
  return status;
}

function countProjectStatuses(projects = []) {
  const counts = {};
  for (const project of projects) {
    const status = displayProjectStatus(project);
    counts[status] = (counts[status] || 0) + 1;
  }
  return counts;
}

function statusFromStats(stats = {}) {
  const approved = Number(stats.approved_projects) || 0;
  const pending = Number(stats.pending_projects) || 0;
  const failed = Number(stats.rejected_projects) || 0;
  const incidents = Number(stats.incident_projects) || 0;
  const total = Number(stats.total_projects) || 0;
  const accounted = approved + pending + failed + incidents;
  const other = Math.max(0, total - accounted);
  return {
    Approved: approved,
    Pending: pending,
    Failed: failed,
    'Incident Detected': incidents,
    Other: other,
  };
}

function remapStatusCounts(source = {}) {
  const counts = {};
  for (const [label, count] of Object.entries(source)) {
    const key = label === 'Monitoring Enabled' ? 'Approved' : label;
    counts[key] = (counts[key] || 0) + (Number(count) || 0);
  }
  return counts;
}

function pickStatusSource(projects, analytics, stats) {
  const fromProjects = countProjectStatuses(projects);
  if (chartTotal(Object.values(fromProjects))) return fromProjects;
  const fromAnalytics = remapStatusCounts(analytics?.project_status || {});
  if (chartTotal(Object.values(fromAnalytics))) return fromAnalytics;
  return statusFromStats(stats);
}

const SCORE_BANDS = [
  { keys: ['90-100'], label: '90–100', hint: 'Excellent', bar: 'bg-emerald-400', chip: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/25' },
  { keys: ['75-89'], label: '75–89', hint: 'Strong', bar: 'bg-cyan-400', chip: 'text-cyan-300 bg-cyan-500/10 border-cyan-500/25' },
  { keys: ['65-74', '60-74'], label: '65–74', hint: 'Meets gate (≥65)', bar: 'bg-indigo-400', chip: 'text-indigo-200 bg-indigo-500/15 border-indigo-400/40' },
  { keys: ['40-64', '40-59'], label: '40–64', hint: 'Below approval gate', bar: 'bg-amber-400', chip: 'text-amber-300 bg-amber-500/10 border-amber-500/25' },
  { keys: ['0-39'], label: '0–39', hint: 'Critical risk', bar: 'bg-rose-400', chip: 'text-rose-300 bg-rose-500/10 border-rose-500/25' },
];

function bandCount(scoreDist, keys) {
  return keys.reduce((sum, key) => sum + (Number(scoreDist?.[key]) || 0), 0);
}

export default function Dashboard() {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [projects, setProjects] = useState([]);

  useEffect(() => {
    Promise.all([api.get('/dashboard'), api.get('/projects')])
      .then(([dash, proj]) => {
        setData(dash.data);
        setProjects(proj.data?.projects || []);
      })
      .catch(console.error);
  }, []);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-primary-500" />
      </div>
    );
  }

  const { stats = {}, notifications, security_tips, recent_activities, analytics = {} } = data;
  const pipeline = analytics.pipeline || {};
  const scoreDist = analytics.score_distribution || {};
  const findings = analytics.findings_by_severity || {};
  const threatsByType = analytics.threats_by_type || {};
  const incidentsBySeverity = analytics.incidents_by_severity || {};

  const statusSource = pickStatusSource(projects, analytics, stats);
  const statusEntries = Object.entries(statusSource).filter(([, count]) => Number(count) > 0);
  const projectChart = {
    labels: statusEntries.map(([label]) => label),
    datasets: [{
      data: statusEntries.map(([, count]) => count),
      backgroundColor: statusEntries.map(([label]) => STATUS_COLORS[label] || '#6366f1'),
      borderWidth: 2,
      borderColor: '#111827',
      hoverOffset: 6,
    }],
  };

  const findingsChart = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [findings.Critical || 0, findings.High || 0, findings.Medium || 0, findings.Low || 0],
      backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
      borderWidth: 0,
    }],
  };

  const scoreTotal = chartTotal(Object.values(scoreDist));
  const scoreMax = Math.max(1, ...SCORE_BANDS.map((band) => bandCount(scoreDist, band.keys)));
  const ops = data.ops || {};
  const phaseGate = ops.phase_gate || {
    phase1_scanned: pipeline.scanned || 0,
    phase1_approved: stats.approved_projects || 0,
    phase1_pending: stats.pending_projects || 0,
    phase2_monitoring: stats.monitoring_enabled || 0,
    phase2_live: stats.active_monitoring || 0,
    phase3_open: (analytics.incidents_by_status?.Open || 0) + (analytics.incidents_by_status?.['In Progress'] || 0),
    phase3_resolved: stats.resolved_incidents || 0,
    approval_gate: 65,
  };
  const attentionQueue = ops.attention_queue || [];
  const detection = ops.detection_confidence || {
    threshold: 85,
    validated_threats: 0,
    observation_threats: Math.max(0, (stats.total_threats || 0) - (stats.total_incidents || 0)),
    open_incidents: phaseGate.phase3_open || 0,
    avg_confidence: 0,
    total_threats: stats.total_threats || 0,
  };

  const pipelineChart = {
    labels: ['Scanned', 'Approved', 'Monitoring', 'Threats', 'Incidents', 'Resolved'],
    datasets: [{
      label: 'Pipeline volume',
      data: [
        pipeline.scanned || 0,
        pipeline.approved || 0,
        pipeline.monitoring || 0,
        pipeline.threats || 0,
        pipeline.incidents || 0,
        pipeline.resolved || 0,
      ],
      borderColor: '#22d3ee',
      backgroundColor: 'rgba(34, 211, 238, 0.15)',
      fill: true,
      tension: 0.35,
    }],
  };

  const threatTypeChart = {
    labels: Object.keys(threatsByType).length ? Object.keys(threatsByType) : ['None'],
    datasets: [{
      label: 'Threats',
      data: Object.keys(threatsByType).length ? Object.values(threatsByType) : [0],
      backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#06b6d4', '#84cc16', '#ec4899', '#14b8a6', '#a855f7'],
      borderRadius: 6,
    }],
  };

  const incidentSeverityChart = {
    labels: Object.keys(incidentsBySeverity).length ? Object.keys(incidentsBySeverity) : ['None'],
    datasets: [{
      data: Object.keys(incidentsBySeverity).length ? Object.values(incidentsBySeverity) : [0],
      backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e'],
      borderWidth: 0,
    }],
  };

  return (
    <div className="space-y-6">
      <div className="page-hero">
        <div>
          <p className="text-xs uppercase tracking-[0.18em] text-primary-300/80">Operations overview</p>
          <h1 className="font-display text-2xl font-bold mt-1">Welcome, {user?.name}</h1>
          <p className="text-gray-400 mt-1">Phase 1 scan · Phase 2 monitoring · Phase 3 response — live analytics</p>
        </div>
        <div className="hidden sm:flex items-center gap-2 text-xs">
          <span className="chip-soft">Gate {phaseGate.approval_gate || 65}/100</span>
          <span className="chip-soft">AI ≥ {detection.threshold || 85}%</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-4">
        <StatCard icon={FiFolder} label="Projects" value={stats.total_projects} color="bg-primary-600" delay={0} />
        <StatCard icon={FiTrendingUp} label="Avg Score" value={stats.avg_security_score ?? 0} suffix="/100" color="bg-indigo-600" delay={0.05} />
        <StatCard icon={FiCheckCircle} label="Approved" value={stats.approved_projects} color="bg-success-600" delay={0.1} />
        <StatCard icon={FiActivity} label="Live Monitors" value={stats.active_monitoring ?? stats.monitoring_enabled} color="bg-accent-600" delay={0.15} />
        <StatCard icon={FiShield} label="Threats" value={stats.total_threats} color="bg-amber-600" delay={0.2} />
        <StatCard icon={FiAlertTriangle} label="Incidents" value={stats.total_incidents} color="bg-danger-600" delay={0.25} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <FiLayers className="text-primary-400" />
            <h3 className="font-semibold">Phase Gate</h3>
          </div>
          <p className="text-xs text-gray-500 mb-3">Live hand-off across Phase 1, 2 and 3. Approval still requires score ≥ 65.</p>
          <div className="space-y-3">
            {[
              { label: 'Phase 1 · Scan & approve', to: '/projects', value: `${phaseGate.phase1_approved || 0} approved`, sub: `${phaseGate.phase1_pending || 0} pending · ${phaseGate.phase1_scanned || 0} scanned`, tone: 'bg-emerald-400' },
              { label: 'Phase 2 · Monitoring', to: '/monitoring', value: `${phaseGate.phase2_live || 0} live`, sub: `${phaseGate.phase2_monitoring || 0} enabled`, tone: 'bg-cyan-400' },
              { label: 'Phase 3 · Incidents', to: '/incidents', value: `${phaseGate.phase3_open || 0} open`, sub: `${phaseGate.phase3_resolved || 0} resolved`, tone: 'bg-rose-400' },
            ].map((row) => (
              <Link key={row.label} to={row.to} className="block rounded-lg border border-white/5 bg-white/[0.03] px-3 py-2 hover:border-primary-500/30">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm text-gray-200">{row.label}</span>
                  <span className="text-sm font-semibold">{row.value}</span>
                </div>
                <div className="mt-1.5 h-1.5 rounded-full bg-gray-800 overflow-hidden">
                  <div className={`h-full ${row.tone} w-2/3`} />
                </div>
                <p className="text-[11px] text-gray-500 mt-1">{row.sub}</p>
              </Link>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <FiList className="text-amber-400" />
              <h3 className="font-semibold">Analyst Queue</h3>
            </div>
            <Link to="/incidents" className="text-xs text-primary-400 hover:underline">Open incidents</Link>
          </div>
          <p className="text-xs text-gray-500 mb-3">Phase 3 cases still Open or In Progress, ranked by severity.</p>
          <div className="space-y-2">
            {attentionQueue.map((item) => (
              <Link key={item.incident_id} to={`/incidents/${item.incident_id}`}
                className="flex items-center justify-between gap-3 rounded-lg border border-white/5 bg-white/[0.03] px-3 py-2 hover:border-amber-500/30">
                <div className="min-w-0">
                  <p className="text-sm font-medium truncate">{item.incident_id} · {item.threat || 'Threat'}</p>
                  <p className="text-[11px] text-gray-500">{item.project_id} · {item.status || 'Open'}</p>
                </div>
                <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${
                  item.severity === 'Critical' ? 'text-rose-300 border-rose-500/30 bg-rose-500/10'
                    : item.severity === 'High' ? 'text-orange-300 border-orange-500/30 bg-orange-500/10'
                    : 'text-amber-300 border-amber-500/30 bg-amber-500/10'
                }`}>{item.severity || 'Medium'}</span>
              </Link>
            ))}
            {!attentionQueue.length && (
              <p className="text-sm text-gray-500 py-6 text-center">No open incidents. Phase 3 queue is clear.</p>
            )}
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <FiCpu className="text-cyan-400" />
            <h3 className="font-semibold">Detection Confidence</h3>
          </div>
          <p className="text-xs text-gray-500 mb-3">Phase 2 Isolation Forest / Random Forest — incidents fire at ≥ {detection.threshold || 85}% confidence.</p>
          <div className="flex items-end justify-between mb-4">
            <div>
              <p className="text-3xl font-display font-bold">{detection.avg_confidence ?? 0}<span className="text-lg text-gray-500">%</span></p>
              <p className="text-xs text-gray-500">Average AI confidence</p>
            </div>
            <FiTarget className="text-2xl text-cyan-400/80" />
          </div>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div className="rounded-lg bg-rose-500/10 border border-rose-500/20 px-3 py-2">
              <p className="text-lg font-semibold text-rose-300">{detection.validated_threats ?? 0}</p>
              <p className="text-[11px] text-gray-400">Validated (≥{detection.threshold || 85}%)</p>
            </div>
            <div className="rounded-lg bg-slate-500/10 border border-white/10 px-3 py-2">
              <p className="text-lg font-semibold text-gray-200">{detection.observation_threats ?? 0}</p>
              <p className="text-[11px] text-gray-400">Observations</p>
            </div>
            <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 px-3 py-2">
              <p className="text-lg font-semibold text-amber-300">{detection.open_incidents ?? 0}</p>
              <p className="text-[11px] text-gray-400">Open in Phase 3</p>
            </div>
            <div className="rounded-lg bg-cyan-500/10 border border-cyan-500/20 px-3 py-2">
              <p className="text-lg font-semibold text-cyan-300">{detection.total_threats ?? 0}</p>
              <p className="text-[11px] text-gray-400">Threats logged</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card">
          <h3 className="font-semibold mb-4">Project Status</h3>
          <div className="h-56">
            <DoughnutChart data={projectChart} cutout="65%" />
          </div>
        </div>
        <div className="card">
          <h3 className="font-semibold mb-4">Findings by Severity (Phase 1)</h3>
          <div className="h-56">
            <DoughnutChart data={findingsChart} />
          </div>
        </div>
        <div className="card">
          <h3 className="font-semibold mb-4">Incident Severity (Phase 3)</h3>
          <div className="h-56">
            <DoughnutChart data={incidentSeverityChart} />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <div className="card lg:col-span-2">
          <div className="flex items-start justify-between gap-3 mb-3">
            <div>
              <h3 className="font-semibold">Security Score</h3>
              <p className="text-xs text-gray-500 mt-0.5">Projects by score band · approval gate is 65/100</p>
            </div>
            <span className="text-sm font-semibold text-primary-300">{stats.avg_security_score ?? 0}<span className="text-gray-500 font-normal">/100 avg</span></span>
          </div>
          <div className="space-y-2">
            {SCORE_BANDS.map((band) => {
              const count = bandCount(scoreDist, band.keys);
              const width = scoreTotal ? Math.max(count ? 8 : 0, Math.round((count / scoreMax) * 100)) : 0;
              return (
                <div key={band.label} className={`rounded-lg border px-2.5 py-1.5 ${band.chip}`}>
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-semibold">{band.label}</span>
                    <span className="text-gray-300">{count} project{count === 1 ? '' : 's'}</span>
                  </div>
                  <div className="mt-1 h-1.5 rounded-full bg-black/30 overflow-hidden">
                    <div className={`h-full ${band.bar}`} style={{ width: `${width}%` }} />
                  </div>
                  <p className="text-[10px] text-gray-400 mt-0.5">{band.hint}</p>
                </div>
              );
            })}
          </div>
        </div>
        <div className="card lg:col-span-3">
          <h3 className="font-semibold mb-4">End-to-End Pipeline (Phase 1 → 2 → 3)</h3>
          <div className="relative h-52">
            <Line data={pipelineChart} options={{
              ...barOpts,
              plugins: { legend: { display: false } },
            }} />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card lg:col-span-2">
          <h3 className="font-semibold mb-4">Threat Types Detected (Phase 2 AI)</h3>
          <div className="relative h-56">
            <Bar data={threatTypeChart} options={{
              ...barOpts,
              indexAxis: 'y',
            }} />
          </div>
        </div>
        <div className="card">
          <h3 className="font-semibold mb-4 flex items-center gap-2"><FiShield className="text-primary-400" /> Security Tips</h3>
          <ul className="space-y-3">
            {(security_tips || []).map((tip, i) => (
              <li key={i} className="text-sm text-gray-400 flex gap-2">
                <span className="text-primary-400 shrink-0">•</span>{tip}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold">Recent Activities</h3>
            <Link to="/projects" className="text-sm text-primary-400 hover:underline">View All</Link>
          </div>
          <div className="space-y-3">
            {(recent_activities || []).map((a, i) => (
              <div key={i} className="flex items-center gap-3 p-3 bg-gray-800/50 rounded-lg">
                <FiClock className="text-gray-500" />
                <div>
                  <p className="text-sm">{a.message}</p>
                  <p className="text-xs text-gray-500">{a.date ? new Date(a.date).toLocaleString() : ''}</p>
                </div>
              </div>
            ))}
            {!recent_activities?.length && <p className="text-sm text-gray-500">No recent activity yet.</p>}
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold">Notifications</h3>
            <Link to="/notifications" className="text-sm text-primary-400 hover:underline">View All</Link>
          </div>
          <div className="space-y-3">
            {(notifications || []).slice(0, 5).map((n) => (
              <div key={n.id} className={`p-3 rounded-lg ${n.read ? 'bg-gray-800/30' : 'bg-primary-600/10 border border-primary-500/20'}`}>
                <p className="text-sm font-medium">{n.title}</p>
                <p className="text-xs text-gray-400 mt-1">{n.message}</p>
              </div>
            ))}
            {!notifications?.length && <p className="text-sm text-gray-500">No notifications.</p>}
          </div>
        </div>
      </div>
    </div>
  );
}
