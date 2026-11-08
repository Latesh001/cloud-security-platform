import { useEffect, useState } from 'react';
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale,
  BarElement, PointElement, LineElement, Filler,
} from 'chart.js';
import { Doughnut, Line } from 'react-chartjs-2';
import api, { downloadFile } from '../../services/api';
import { Empty, Metric, Notice } from './shared';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler);

const valueLabels = {
  id: 'unifiedValueLabels',
  afterDatasetsDraw(chart) {
    if (!chart.options.plugins?.unifiedValueLabels) return;
    const { ctx } = chart;
    ctx.save();
    ctx.font = '600 11px Inter, system-ui, sans-serif';
    ctx.fillStyle = '#e5e7eb';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'bottom';
    chart.data.datasets.forEach((dataset, datasetIndex) => {
      const meta = chart.getDatasetMeta(datasetIndex);
      if (meta.type === 'doughnut' || meta.hidden) return;
      meta.data.forEach((element, index) => {
        const raw = Number(dataset.data[index]);
        if (!Number.isFinite(raw)) return;
        const pos = element.tooltipPosition();
        ctx.fillText(String(raw), pos.x, pos.y - 6);
      });
    });
    ctx.restore();
  },
};

ChartJS.register(valueLabels);

const axisTicks = { color: '#d1d5db', precision: 0, font: { size: 11 } };
const axisGrid = { color: 'rgba(75, 85, 99, 0.45)' };

const lineOpts = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false },
    tooltip: { enabled: true },
    unifiedValueLabels: true,
  },
  scales: {
    x: { ticks: { ...axisTicks, maxRotation: 45, minRotation: 0 }, grid: { display: false } },
    y: { ticks: axisTicks, grid: axisGrid, beginAtZero: true, suggestedMax: 1 },
  },
};

const doughnutOpts = {
  responsive: true,
  maintainAspectRatio: false,
  cutout: '58%',
  plugins: {
    legend: {
      position: 'bottom',
      labels: { color: '#d1d5db', boxWidth: 12, padding: 12, font: { size: 11 } },
    },
    tooltip: { enabled: true },
  },
};

function shortDay(iso) {
  if (!iso || iso.length < 10) return iso || '';
  const date = new Date(`${iso.slice(0, 10)}T00:00:00`);
  if (Number.isNaN(date.getTime())) return iso.slice(5);
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function Readings({ labels, values, suffix = '' }) {
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      {labels.map((label, index) => (
        <span key={`${label}-${index}`} className="text-xs bg-gray-800/70 border border-gray-700 rounded-md px-2 py-1 text-gray-200">
          {label}: <strong>{values[index] ?? 0}{suffix}</strong>
        </span>
      ))}
    </div>
  );
}

export default function UnifiedDashboard() {
  const [data, setData] = useState(null);
  const [risk, setRisk] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.get('/advanced/dashboard')
      .then((dash) => setData(dash.data))
      .catch((err) => setError(err.response?.data?.error || 'Could not load the unified dashboard.'));
    api.get('/advanced/ai/risk').then((pred) => setRisk(pred.data)).catch(() => {});
  }, []);

  if (error) return <Notice type="error">{error}</Notice>;
  if (!data) return <p className="text-sm text-gray-500">Loading unified dashboard…</p>;

  const m = data.metrics || {};
  const c = data.charts || {};
  const pieEntries = Object.entries(c.severity_pie || {});
  const pieLabels = pieEntries.map(([label]) => label);
  const pieValues = pieEntries.map(([, value]) => Number(value) || 0);
  const pieTotal = pieValues.reduce((sum, value) => sum + value, 0);
  const riskLabels = Object.keys(c.risk_distribution || {});
  const riskValues = riskLabels.map((label) => Number(c.risk_distribution[label]) || 0);
  const riskTotal = riskValues.reduce((sum, value) => sum + value, 0);
  const trendLabels = Object.keys(c.attack_trend || {}).map(shortDay);
  const trendValues = Object.values(c.attack_trend || {}).map((value) => Number(value) || 0);
  const history = c.score_history || [];
  const historyLabels = history.map((row, index) => row.label || row.project_id || `Scan ${index + 1}`);
  const historyValues = history.map((row) => Number(row.score) || 0);
  const trendMax = Math.max(1, ...trendValues);

  return (
    <div className="space-y-6">
      <div className="page-hero">
        <div>
          <h1 className="font-display text-2xl font-bold">Unified Security Dashboard</h1>
          <p className="text-gray-400">Live Phase 1 → 2 → 3 picture for your projects.</p>
        </div>
        <button
          className="btn-secondary"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try { await downloadFile('/advanced/reports/executive', 'executive_dashboard.pdf'); }
            catch { setNotice('Executive PDF could not be generated.'); }
            finally { setBusy(false); }
          }}
        >
          {busy ? 'Preparing…' : 'Executive PDF'}
        </button>
      </div>
      {notice && <Notice type="error">{notice}</Notice>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Metric label="Uploaded Projects" value={m.uploaded_projects} />
        <Metric label="Avg Score" value={`${m.security_score ?? 0}/100`} />
        <Metric label="Vulnerabilities" value={m.vulnerabilities_found} />
        <Metric label="Cloud Assets" value={m.cloud_assets} />
        <Metric label="Active Alerts" value={m.active_alerts} />
        <Metric label="Critical Incidents" value={m.critical_incidents} />
        <Metric label="Automated Responses" value={m.automated_responses} />
        <Metric label="Compliance" value={`${m.compliance_status ?? 0}%`} />
      </div>

      {risk && (
        <div className="card">
          <h3 className="font-semibold mb-2">AI Risk Prediction</h3>
          <p className="text-sm text-gray-300">
            Residual risk <strong>{risk.risk_score}</strong> ({risk.level}). {risk.recommendation}
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="font-semibold mb-3">Severity</h3>
          <div className="relative h-64">
            {pieTotal ? (
              <Doughnut
                data={{
                  labels: pieLabels.map((label, index) => `${label} (${pieValues[index]})`),
                  datasets: [{
                    data: pieValues,
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e'],
                    borderWidth: 0,
                  }],
                }}
                options={doughnutOpts}
              />
            ) : <Empty title="No incidents yet" text="Severity slices appear after Phase 3 activity." />}
          </div>
          {pieTotal > 0 && <Readings labels={pieLabels} values={pieValues} />}
        </div>

        <div className="card">
          <h3 className="font-semibold mb-1">Risk distribution</h3>
          <p className="text-xs text-gray-500 mb-3">Phase 1 findings by severity. Bar length is share of total findings.</p>
          {riskTotal ? (
            <div className="space-y-2.5">
              {[
                { key: 'Critical', color: 'bg-red-500', hint: 'Fix immediately' },
                { key: 'High', color: 'bg-orange-500', hint: 'Remediate soon' },
                { key: 'Medium', color: 'bg-yellow-500', hint: 'Plan a fix' },
                { key: 'Low', color: 'bg-blue-500', hint: 'Monitor' },
              ].map((band) => {
                const count = Number(c.risk_distribution?.[band.key]) || 0;
                const pct = Math.round((count / riskTotal) * 100);
                return (
                  <div key={band.key} className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium text-gray-100">{band.key}</span>
                      <span className="font-semibold">{count} <span className="text-gray-500 font-normal">({pct}%)</span></span>
                    </div>
                    <div className="mt-1.5 h-2.5 rounded-full bg-gray-800 overflow-hidden">
                      <div className={`h-full ${band.color}`} style={{ width: `${Math.max(count ? 6 : 0, pct)}%` }} />
                    </div>
                    <p className="text-[11px] text-gray-500 mt-1">{band.hint}</p>
                  </div>
                );
              })}
              <p className="text-xs text-gray-400 pt-1">Total findings: <strong className="text-gray-200">{riskTotal}</strong></p>
            </div>
          ) : (
            <Empty title="No Phase 1 findings yet" text="Upload and scan a project to populate this risk breakdown." />
          )}
        </div>

        <div className="card">
          <h3 className="font-semibold mb-3">Attack trend</h3>
          <div className="relative h-64">
            <Line
              data={{
                labels: trendLabels.length ? trendLabels : ['now'],
                datasets: [{
                  label: 'Attacks',
                  data: trendLabels.length ? trendValues : [0],
                  borderColor: '#22d3ee',
                  backgroundColor: 'rgba(34,211,238,0.18)',
                  fill: true,
                  tension: 0.35,
                  borderWidth: 3,
                  pointRadius: 4,
                  pointHoverRadius: 6,
                  pointBackgroundColor: '#22d3ee',
                  spanGaps: true,
                }],
              }}
              options={{
                ...lineOpts,
                scales: { ...lineOpts.scales, y: { ...lineOpts.scales.y, suggestedMax: trendMax } },
              }}
            />
          </div>
          <Readings labels={trendLabels} values={trendValues} />
        </div>

        <div className="card">
          <h3 className="font-semibold mb-3">Security score history</h3>
          <div className="relative h-64">
            {history.length ? (
              <Line
                data={{
                  labels: historyLabels,
                  datasets: [{
                    label: 'Score',
                    data: historyValues,
                    borderColor: '#a78bfa',
                    backgroundColor: 'rgba(167,139,250,0.16)',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 3,
                    pointRadius: 5,
                    pointHoverRadius: 7,
                    pointBackgroundColor: '#a78bfa',
                    spanGaps: true,
                  }],
                }}
                options={{
                  ...lineOpts,
                  scales: {
                    ...lineOpts.scales,
                    y: { ...lineOpts.scales.y, max: 100, suggestedMax: 100 },
                  },
                }}
              />
            ) : <Empty title="No scans yet" text="Upload a ZIP in Phase 1 to start the score history." />}
          </div>
          {history.length > 0 && <Readings labels={historyLabels} values={historyValues} suffix="/100" />}
        </div>
      </div>

      <div className="card">
        <h3 className="font-semibold mb-3">Incident timeline</h3>
        {(c.incident_timeline || []).length === 0 ? (
          <p className="text-sm text-gray-500">No workflow events yet.</p>
        ) : (
          <div className="space-y-2">
            {c.incident_timeline.map((row) => (
              <div key={row.project_id} className="flex justify-between text-sm bg-gray-800/40 rounded-lg px-3 py-2">
                <span>{row.project_id} · {row.status}</span>
                <span className="text-gray-500">{row.incident || 'No incident'} · {row.updated_at ? new Date(row.updated_at).toLocaleString() : ''}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
