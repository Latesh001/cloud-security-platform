import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale,
  BarElement, PointElement, LineElement,
} from 'chart.js';
import { Doughnut, Line } from 'react-chartjs-2';
import {
  FiArrowLeft, FiDownload, FiRefreshCw, FiUploadCloud, FiPlay, FiFileText,
  FiCpu, FiLayers, FiClock, FiFolder, FiAlertTriangle, FiCheckCircle,
} from 'react-icons/fi';
import api, { downloadFile } from '../services/api';
import {
  Alert, EmptyState, Loader, PageHeader, ScoreRing, SeverityBadge,
  StatusBadge, formatDate,
} from '../components/ui';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale,
  BarElement, PointElement, LineElement);

export default function ProjectDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');

  const load = useCallback(async () => {
    try {
      const { data: result } = await api.get(`/phase1/result/${id}`);
      setData(result);
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || 'Could not load this project.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const rescan = async () => {
    setBusy('rescan');
    setError('');
    setNotice('');
    try {
      await api.post(`/phase1/rescan/${id}`);
      await load();
      setNotice('Rescan complete. The report below reflects the latest assessment.');
    } catch (err) {
      setError(err.response?.data?.error || 'Rescan failed.');
    } finally {
      setBusy('');
    }
  };

  const reupload = async (file) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setError('Only ZIP archives are accepted.');
      return;
    }
    if (file.size > 1000 * 1024 * 1024) {
      setError('The archive exceeds the 1000 MB limit.');
      return;
    }
    setBusy('upload');
    setError('');
    setNotice('');

    const formData = new FormData();
    formData.append('file', file);
    try {
      const { data: result } = await api.post(`/projects/upload/${id}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 30 * 60 * 1000,
      });
      if (result.scan?.error) {
        setError(result.scan.error);
      } else {
        setNotice('New archive uploaded and reassessed.');
      }
      await load();
    } catch (err) {
      setError(err.response?.data?.error || 'Upload failed.');
    } finally {
      setBusy('');
    }
  };

  const startMonitoring = async () => {
    setBusy('monitor');
    setError('');
    setNotice('');
    try {
      await api.post(`/monitoring/start/${id}`);
      navigate('/monitoring');
    } catch (err) {
      setError(err.response?.data?.error || 'Monitoring could not be started.');
      setBusy('');
    }
  };

  const download = async () => {
    setBusy('download');
    setError('');
    try {
      await downloadFile(`/phase1/report/${id}`, `security_report_${id}.pdf`);
    } catch {
      setError('The PDF report is not available yet. Run a scan first.');
    } finally {
      setBusy('');
    }
  };

  if (loading) return <Loader label="Loading project assessment..." />;

  if (error && !data) {
    return (
      <div className="space-y-4">
        <Alert type="error">{error}</Alert>
        <Link to="/projects" className="btn-secondary inline-block">Back to Projects</Link>
      </div>
    );
  }

  const { project, report, findings = [], technologies = {}, detector_summary = {},
    files_scanned = 0, scan_duration = 0, history = [] } = data;

  const hasScan = Boolean(report?.report_id);
  const severities = ['Critical', 'High', 'Medium', 'Low'];
  const visibleFindings = severityFilter === 'All'
    ? findings
    : findings.filter((f) => f.severity === severityFilter);

  const severityChart = {
    labels: severities,
    datasets: [{
      data: severities.map((s) => report?.[s.toLowerCase()] ?? 0),
      backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6'],
      borderWidth: 0,
    }],
  };

  const trendChart = {
    labels: history.slice().reverse().map((_, i) => `Scan ${i + 1}`),
    datasets: [{
      label: 'Security Score',
      data: history.slice().reverse().map((h) => h.score),
      borderColor: '#3b82f6',
      backgroundColor: 'rgba(59,130,246,0.15)',
      fill: true,
      tension: 0.35,
      pointBackgroundColor: '#3b82f6',
    }],
  };

  return (
    <div className="space-y-6">
      <PageHeader title={project.project_name} subtitle={`${project.project_id} · ${project.category}`}>
        <button onClick={() => navigate('/projects')} className="btn-secondary flex items-center gap-2">
          <FiArrowLeft /> Back
        </button>
      </PageHeader>

      {error && <Alert type="error">{error}</Alert>}
      {notice && <Alert type="success">{notice}</Alert>}

      {!hasScan ? (
        <EmptyState
          icon={FiUploadCloud}
          title="No assessment yet"
          description="Upload a ZIP archive of the project source to run the Phase 1 security assessment."
          action={
            <>
              <input ref={fileInputRef} type="file" accept=".zip" className="hidden"
                onChange={(e) => reupload(e.target.files?.[0])} />
              <button onClick={() => fileInputRef.current?.click()} disabled={busy === 'upload'}
                className="btn-primary">
                {busy === 'upload' ? 'Uploading and scanning...' : 'Upload Project ZIP'}
              </button>
            </>
          }
        />
      ) : (
        <>
          {/* Score summary */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="card flex flex-col items-center justify-center text-center">
              <ScoreRing score={report.score} />
              <div className="mt-4 space-y-2">
                <StatusBadge status={project.status} />
                <p className="text-sm text-gray-500">Risk level: {report.risk_level}</p>
              </div>
            </div>

            <div className="card">
              <h3 className="font-semibold mb-4">Severity Distribution</h3>
              <div className="h-48 flex items-center justify-center">
                {findings.length > 0 ? (
                  <Doughnut
                    data={severityChart}
                    options={{
                      maintainAspectRatio: false,
                      cutout: '62%',
                      plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af', boxWidth: 12, padding: 12 } } },
                    }}
                  />
                ) : (
                  <div className="text-center">
                    <FiCheckCircle className="text-4xl text-success-500 mx-auto mb-2" />
                    <p className="text-sm text-gray-400">No findings detected</p>
                  </div>
                )}
              </div>
            </div>

            <div className="card space-y-4">
              <h3 className="font-semibold">Scan Summary</h3>
              <div className="space-y-3 text-sm">
                {[
                  [FiFolder, 'Files scanned', files_scanned],
                  [FiClock, 'Scan duration', `${scan_duration}s`],
                  [FiCpu, 'Language', project.programming_language || 'Not detected'],
                  [FiLayers, 'Framework', project.framework || 'General'],
                  [FiFileText, 'Last scan', formatDate(report.created_date)],
                ].map(([Icon, label, value]) => (
                  <div key={label} className="flex items-center justify-between gap-3">
                    <span className="flex items-center gap-2 text-gray-500">
                      <Icon className="shrink-0" /> {label}
                    </span>
                    <span className="text-gray-200 text-right truncate">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Approval banner */}
          <Alert type={report.approval_status === 'Approved' ? 'success' : 'warning'}>
            <div className="flex items-start gap-3">
              {report.approval_status === 'Approved'
                ? <FiCheckCircle className="mt-0.5 shrink-0 text-lg" />
                : <FiAlertTriangle className="mt-0.5 shrink-0 text-lg" />}
              <div>
                <p className="font-medium">
                  {report.approval_status === 'Approved'
                    ? 'Approved for cloud security monitoring'
                    : 'Pending remediation'}
                </p>
                <p className="mt-1 opacity-90">
                  {report.approval_status === 'Approved'
                    ? `This project scored ${report.score}/100 (gate is 65), so Phase 2 monitoring is unlocked.`
                    : report.score >= 65 && report.critical > 2
                      ? `${report.critical} critical findings exceed the residual-risk allowance. Remediate the highest-severity issues and rescan.`
                      : `The score of ${report.score} is below the required 65. Resolve the high-severity findings and rescan.`}
                </p>
              </div>
            </div>
          </Alert>

          {/* Actions */}
          <div className="flex flex-wrap gap-3">
            <button onClick={download} disabled={busy === 'download'} className="btn-secondary flex items-center gap-2">
              <FiDownload /> {busy === 'download' ? 'Preparing...' : 'Download PDF Report'}
            </button>
            <button onClick={rescan} disabled={busy === 'rescan'} className="btn-secondary flex items-center gap-2">
              <FiRefreshCw className={busy === 'rescan' ? 'animate-spin' : ''} />
              {busy === 'rescan' ? 'Rescanning...' : 'Rescan'}
            </button>
            <input ref={fileInputRef} type="file" accept=".zip" className="hidden"
              onChange={(e) => reupload(e.target.files?.[0])} />
            <button onClick={() => fileInputRef.current?.click()} disabled={busy === 'upload'}
              className="btn-secondary flex items-center gap-2">
              <FiUploadCloud /> {busy === 'upload' ? 'Uploading...' : 'Upload Fixed Version'}
            </button>
            <Link to={`/projects/${id}/report`} className="btn-secondary flex items-center gap-2">
              <FiFileText /> Detailed Report
            </Link>
            {(project.monitoring_enabled || report.approval_status === 'Approved' || report.score >= 65) && (
              <button onClick={startMonitoring} disabled={busy === 'monitor'} className="btn-primary flex items-center gap-2">
                <FiPlay /> {busy === 'monitor' ? 'Starting...' : 'Start Monitoring'}
              </button>
            )}
          </div>

          {/* Detected technologies and detector breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="font-semibold mb-4">Detected Technologies</h3>
              <div className="space-y-3 text-sm">
                {[
                  ['Languages', technologies.languages],
                  ['Frameworks', technologies.frameworks],
                  ['Package Managers', technologies.package_managers],
                  ['Databases', technologies.databases],
                  ['Cloud Configuration', technologies.cloud_configs],
                ].map(([label, values]) => (
                  <div key={label}>
                    <p className="text-gray-500 text-xs mb-1.5">{label}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {values?.length > 0
                        ? values.map((v) => (
                          <span key={v} className="px-2 py-0.5 rounded-md bg-gray-800 text-gray-300 text-xs border border-gray-700">
                            {v}
                          </span>
                        ))
                        : <span className="text-gray-600 text-xs">None detected</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="card">
              <h3 className="font-semibold mb-4">Findings by Detector</h3>
              {Object.keys(detector_summary).length > 0 ? (
                <div className="space-y-3">
                  {Object.entries(detector_summary)
                    .sort((a, b) => b[1] - a[1])
                    .map(([detector, count]) => {
                      const total = Object.values(detector_summary).reduce((a, b) => a + b, 0);
                      return (
                        <div key={detector}>
                          <div className="flex justify-between text-sm mb-1">
                            <span className="text-gray-300">{detector}</span>
                            <span className="text-gray-500">{count}</span>
                          </div>
                          <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                            <motion.div
                              className="h-full bg-gradient-to-r from-primary-500 to-accent-500"
                              initial={{ width: 0 }}
                              animate={{ width: `${(count / total) * 100}%` }}
                              transition={{ duration: 0.6 }}
                            />
                          </div>
                        </div>
                      );
                    })}
                </div>
              ) : (
                <p className="text-sm text-gray-500">No findings were reported by any detector.</p>
              )}

              {history.length > 1 && (
                <div className="mt-6 pt-4 border-t border-gray-800">
                  <p className="text-sm font-medium mb-3">Score Trend</p>
                  <div className="h-32">
                    <Line
                      data={trendChart}
                      options={{
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                          y: { min: 0, max: 100, ticks: { color: '#6b7280' }, grid: { color: '#1f2937' } },
                          x: { ticks: { color: '#6b7280' }, grid: { display: false } },
                        },
                      }}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Findings */}
          <div className="card">
            <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
              <h3 className="font-semibold">Findings ({visibleFindings.length})</h3>
              <div className="flex gap-1.5 flex-wrap">
                {['All', ...severities].map((level) => (
                  <button
                    key={level}
                    onClick={() => setSeverityFilter(level)}
                    className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors
                      ${severityFilter === level
                        ? 'bg-primary-600 text-white'
                        : 'bg-gray-800 text-gray-400 hover:text-gray-200'}`}
                  >
                    {level}
                    {level !== 'All' && ` (${report[level.toLowerCase()] ?? 0})`}
                  </button>
                ))}
              </div>
            </div>

            {visibleFindings.length === 0 ? (
              <p className="text-sm text-gray-500 py-6 text-center">
                No {severityFilter === 'All' ? '' : severityFilter.toLowerCase()} findings to show.
              </p>
            ) : (
              <div className="space-y-3 max-h-[32rem] overflow-y-auto pr-1">
                {visibleFindings.slice(0, 100).map((finding, index) => (
                  <div key={`${finding.file}-${finding.line}-${index}`}
                    className="p-4 bg-gray-800/40 rounded-lg border border-gray-800">
                    <div className="flex items-start justify-between gap-3 flex-wrap">
                      <div className="min-w-0">
                        <p className="font-medium text-sm">{finding.problem}</p>
                        <p className="text-xs text-gray-500 font-mono mt-0.5 break-all">
                          {finding.file}:{finding.line}
                        </p>
                      </div>
                      <SeverityBadge severity={finding.severity} />
                    </div>

                    {finding.snippet && (
                      <pre className="mt-2.5 p-2.5 bg-gray-950 rounded text-xs text-gray-400 overflow-x-auto font-mono">
                        {finding.snippet}
                      </pre>
                    )}

                    <div className="mt-2.5 space-y-1 text-xs">
                      <p className="text-gray-400"><span className="text-gray-500">Fix:</span> {finding.solution}</p>
                      <div className="flex justify-between gap-3 flex-wrap text-gray-600">
                        <span>{finding.detector}</span>
                        <span>{finding.reference}</span>
                      </div>
                    </div>
                  </div>
                ))}
                {visibleFindings.length > 100 && (
                  <p className="text-xs text-gray-500 text-center py-2">
                    Showing the first 100 of {visibleFindings.length} findings. Download the PDF for the full list.
                  </p>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
