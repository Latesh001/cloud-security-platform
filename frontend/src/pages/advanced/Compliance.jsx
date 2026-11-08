import { useEffect, useState } from 'react';
import api, { downloadFile } from '../../services/api';
import { Empty, Notice } from './shared';

export default function Compliance() {
  const [reports, setReports] = useState([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');

  const load = () => {
    api.get('/advanced/compliance')
      .then((r) => setReports(r.data.reports || []))
      .catch((err) => setError(err.response?.data?.error || 'Could not load compliance.'));
  };

  useEffect(() => { load(); }, []);

  const download = async (projectId) => {
    setBusy(projectId);
    try {
      await downloadFile(`/advanced/compliance/report?project_id=${encodeURIComponent(projectId)}`, `compliance_${projectId}.pdf`);
    } catch {
      setError('Compliance PDF could not be generated.');
    } finally {
      setBusy('');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Compliance Manager</h1>
        <p className="text-gray-500">ISO 27001, NIST CSF, CIS Controls, GDPR, and HIPAA scored from live Phase 1–3 data.</p>
      </div>
      {error && <Notice type="error">{error}</Notice>}
      {reports.length === 0 ? (
        <Empty title="No projects" text="Scan a project in Phase 1 to generate live control evidence." />
      ) : reports.map((report) => {
        const byFw = {};
        (report.controls || []).forEach((c) => {
          byFw[c.framework] = byFw[c.framework] || [];
          byFw[c.framework].push(c);
        });
        return (
          <div key={report.project_id} className="card space-y-4">
            <div className="flex flex-wrap justify-between gap-3">
              <div>
                <h3 className="font-semibold">{report.project_id}</h3>
                <p className="text-sm text-gray-400">{report.passed} passed · {report.failed} failed · {report.percentage}%</p>
              </div>
              <button className="btn-secondary" disabled={busy === report.project_id} onClick={() => download(report.project_id)}>
                {busy === report.project_id ? 'Preparing…' : 'Download report'}
              </button>
            </div>
            <div className="h-2 rounded-full bg-gray-800 overflow-hidden">
              <div className="h-full bg-primary-500" style={{ width: `${report.percentage || 0}%` }} />
            </div>
            {Object.entries(byFw).map(([fw, controls]) => (
              <div key={fw}>
                <h4 className="text-sm font-medium text-gray-300 mb-2">{fw}</h4>
                <div className="space-y-2">
                  {controls.map((c) => (
                    <div key={c.control_id} className="bg-gray-800/40 rounded-lg px-3 py-2 text-sm">
                      <div className="flex justify-between gap-3">
                        <span>{c.control_id} · {c.title}</span>
                        <span className={c.passed ? 'text-green-400' : 'text-red-400'}>{c.passed ? 'Passed' : 'Failed'}</span>
                      </div>
                      <p className="text-xs text-gray-500 mt-1">{c.reason || c.description}</p>
                      {!c.passed && <p className="text-xs text-amber-400 mt-1">Recommendation: {c.description}</p>}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}
