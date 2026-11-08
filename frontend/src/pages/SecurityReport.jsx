import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { FiArrowLeft, FiDownload, FiPrinter, FiShield } from 'react-icons/fi';
import api, { downloadFile } from '../services/api';
import {
  Alert, EmptyState, Loader, PageHeader, ScoreRing, SeverityBadge, formatDate,
} from '../components/ui';

const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

export default function SecurityReport() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    api.get(`/phase1/result/${id}`)
      .then((r) => setData(r.data))
      .catch((err) => setError(err.response?.data?.error || 'Could not load the report.'))
      .finally(() => setLoading(false));
  }, [id]);

  const download = async () => {
    setDownloading(true);
    try {
      await downloadFile(`/phase1/report/${id}`, `security_report_${id}.pdf`);
    } catch {
      setError('The PDF report is not available. Run a scan first.');
    } finally {
      setDownloading(false);
    }
  };

  if (loading) return <Loader label="Building report..." />;
  if (error && !data) return <Alert type="error">{error}</Alert>;

  const { project, report, findings = [], technologies = {}, history = [] } = data;

  if (!report?.report_id) {
    return (
      <EmptyState
        icon={FiShield}
        title="No report available"
        description="This project has not been assessed yet."
        action={<Link to={`/projects/${id}`} className="btn-primary">Go to Project</Link>}
      />
    );
  }

  const grouped = findings.reduce((acc, finding) => {
    const key = finding.detector || 'Other';
    (acc[key] = acc[key] || []).push(finding);
    return acc;
  }, {});

  Object.values(grouped).forEach((list) => {
    list.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3));
  });

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <PageHeader title="Security Assessment Report" subtitle={`${project.project_id} · ${project.project_name}`}>
        <Link to={`/projects/${id}`} className="btn-secondary flex items-center gap-2">
          <FiArrowLeft /> Back
        </Link>
        <button onClick={() => window.print()} className="btn-secondary flex items-center gap-2">
          <FiPrinter /> Print
        </button>
        <button onClick={download} disabled={downloading} className="btn-primary flex items-center gap-2">
          <FiDownload /> {downloading ? 'Preparing...' : 'Download PDF'}
        </button>
      </PageHeader>

      {error && <Alert type="error">{error}</Alert>}

      {/* Executive summary */}
      <div className="card">
        <div className="flex flex-col sm:flex-row items-center gap-8">
          <ScoreRing score={report.score} />
          <div className="flex-1 w-full space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-sm">
              {[
                ['Project ID', project.project_id],
                ['Category', project.category],
                ['Language', project.programming_language || 'Not detected'],
                ['Framework', project.framework || 'General'],
                ['Risk Level', report.risk_level],
                ['Assessed', formatDate(report.created_date)],
              ].map(([label, value]) => (
                <div key={label}>
                  <p className="text-gray-500 text-xs">{label}</p>
                  <p className="text-gray-200 mt-0.5 break-words">{value}</p>
                </div>
              ))}
            </div>

            <div className={`px-4 py-3 rounded-lg border text-sm font-medium
              ${report.approval_status === 'Approved'
                ? 'bg-green-500/10 border-green-500/30 text-green-400'
                : 'bg-orange-500/10 border-orange-500/30 text-orange-400'}`}>
              Approval Status: {report.approval_status}
            </div>
          </div>
        </div>
      </div>

      {/* Issue summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          ['Critical', report.critical, 'text-red-400', 'border-red-500/30'],
          ['High', report.high, 'text-orange-400', 'border-orange-500/30'],
          ['Medium', report.medium, 'text-yellow-400', 'border-yellow-500/30'],
          ['Low', report.low, 'text-blue-400', 'border-blue-500/30'],
        ].map(([label, value, color, border]) => (
          <div key={label} className={`card border ${border} text-center py-5`}>
            <p className={`text-3xl font-bold ${color}`}>{value}</p>
            <p className="text-xs text-gray-500 mt-1">{label}</p>
          </div>
        ))}
      </div>

      {/* Recommendations */}
      <div className="card">
        <h3 className="font-semibold mb-3">AI Recommendations</h3>
        <pre className="text-sm text-gray-300 whitespace-pre-wrap font-sans leading-relaxed">
          {report.recommendation || 'No recommendations were generated.'}
        </pre>
      </div>

      {/* Technologies */}
      <div className="card">
        <h3 className="font-semibold mb-3">Technology Stack Detected</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-sm">
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
                    <span key={v} className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 text-xs border border-gray-700">
                      {v}
                    </span>
                  ))
                  : <span className="text-gray-600 text-xs">None detected</span>}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Detailed findings by detector */}
      {Object.keys(grouped).length > 0 ? (
        Object.entries(grouped).map(([detector, list]) => (
          <div key={detector} className="card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold">{detector}</h3>
              <span className="text-sm text-gray-500">{list.length} finding{list.length === 1 ? '' : 's'}</span>
            </div>
            <div className="space-y-3">
              {list.map((finding, index) => (
                <div key={`${finding.file}-${finding.line}-${index}`}
                  className="border-l-2 border-gray-700 pl-4 py-1">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <p className="font-medium text-sm">{finding.problem}</p>
                    <SeverityBadge severity={finding.severity} />
                  </div>
                  <p className="text-xs text-gray-500 font-mono mt-1 break-all">
                    {finding.file}:{finding.line}
                  </p>
                  <p className="text-sm text-gray-400 mt-2">{finding.explanation}</p>
                  <p className="text-sm text-gray-300 mt-1.5">
                    <span className="text-gray-500">Recommended fix: </span>{finding.solution}
                  </p>
                  <p className="text-xs text-gray-600 mt-1">Reference: {finding.reference}</p>
                </div>
              ))}
            </div>
          </div>
        ))
      ) : (
        <div className="card text-center py-10">
          <FiShield className="text-4xl text-success-500 mx-auto mb-3" />
          <p className="font-medium">No security findings</p>
          <p className="text-sm text-gray-500 mt-1">
            The assessment found no issues matching the platform's detection rules.
          </p>
        </div>
      )}

      {/* Scan history */}
      {history.length > 0 && (
        <div className="card">
          <h3 className="font-semibold mb-4">Assessment History</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-2 pr-4 font-medium">Date</th>
                  <th className="pb-2 pr-4 font-medium">Score</th>
                  <th className="pb-2 pr-4 font-medium">Critical</th>
                  <th className="pb-2 pr-4 font-medium">High</th>
                  <th className="pb-2 pr-4 font-medium">Medium</th>
                  <th className="pb-2 pr-4 font-medium">Low</th>
                  <th className="pb-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry) => (
                  <tr key={entry.report_id} className="border-b border-gray-800/60 last:border-0">
                    <td className="py-2.5 pr-4 text-gray-400">{formatDate(entry.created_date)}</td>
                    <td className="py-2.5 pr-4 font-medium">{entry.score}</td>
                    <td className="py-2.5 pr-4 text-red-400">{entry.critical}</td>
                    <td className="py-2.5 pr-4 text-orange-400">{entry.high}</td>
                    <td className="py-2.5 pr-4 text-yellow-400">{entry.medium}</td>
                    <td className="py-2.5 pr-4 text-blue-400">{entry.low}</td>
                    <td className="py-2.5 text-gray-300">{entry.approval_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
