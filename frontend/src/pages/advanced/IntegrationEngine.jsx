import { useEffect, useState } from 'react';
import api, { downloadFile } from '../../services/api';
import { Empty, Notice } from './shared';

export default function IntegrationEngine() {
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [shap, setShap] = useState(null);
  const [lime, setLime] = useState(null);
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState('');

  const load = () => {
    api.get('/advanced/integration')
      .then((r) => setRows(r.data.workflows || []))
      .catch((err) => setError(err.response?.data?.error || 'Could not load workflows.'));
  };

  useEffect(() => { load(); }, []);

  const open = async (projectId) => {
    setSelected(projectId);
    try {
      const { data } = await api.get(`/advanced/projects/${projectId}/timeline`);
      setDetail(data);
      const event = (data.alerts && data.alerts[0]) || {};
      const payload = {
        eventType: event.threat || 'ConsoleLogin',
        country: event.country || 'Unknown',
        isSuspicious: true,
        sourceIP: event.source_ip,
      };
      try {
        const [s, l] = await Promise.all([
          api.post('/advanced/ai/shap', payload),
          api.post('/advanced/ai/lime', payload),
        ]);
        setShap(s.data);
        setLime(l.data);
      } catch {
        setShap(null);
        setLime(null);
      }
      const firstIncident = (data.incidents || [])[0];
      if (firstIncident?.incident_id) {
        try {
          const sum = await api.get(`/advanced/ai/summarize/${firstIncident.incident_id}`);
          setSummary(sum.data);
        } catch {
          setSummary(null);
        }
      } else {
        setSummary(null);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Could not load project timeline.');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Phase Integration Engine</h1>
        <p className="text-gray-500">
          Score below 65 blocks deployment. Score 65+ enables Phase 2. Critical detections open Phase 3.
        </p>
      </div>
      {error && <Notice type="error">{error}</Notice>}
      {rows.length === 0 ? (
        <Empty title="No projects" text="Create and scan a project in Phase 1. This board will pick it up automatically." />
      ) : (
        <div className="overflow-x-auto card">
          <table className="w-full text-sm">
            <thead className="text-gray-500 text-left">
              <tr>
                <th className="pb-2">Project</th>
                <th className="pb-2">Score</th>
                <th className="pb-2">Status</th>
                <th className="pb-2">Phase 2</th>
                <th className="pb-2">Deploy</th>
                <th className="pb-2">Incident</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.project_id} className="border-t border-gray-800 cursor-pointer hover:bg-gray-800/40"
                  onClick={() => open(row.project_id)}>
                  <td className="py-2">{row.project_id} · {row.project_name}</td>
                  <td>{row.security_score ?? '—'}</td>
                  <td>{row.status}</td>
                  <td>{row.phase2_enabled ? 'Enabled' : 'Blocked'}</td>
                  <td>{row.deployment_blocked ? 'Blocked' : 'Allowed'}</td>
                  <td>{row.latest_incident || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {detail && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="card">
            <h3 className="font-semibold mb-3">Workflow · {selected}</h3>
            <ol className="space-y-2 text-sm">
              {(detail.workflow?.steps || []).map((step) => (
                <li key={step.name} className="flex items-center gap-2">
                  <span className={`w-2.5 h-2.5 rounded-full ${step.done ? 'bg-green-400' : 'bg-gray-600'}`} />
                  {step.name}
                </li>
              ))}
            </ol>
            <p className="text-xs text-gray-500 mt-4">
              Phase 1 vulns: {(detail.phase1?.vulnerabilities || []).length}.
              Linked incidents: {(detail.incidents || []).length}.
            </p>
            {(detail.incidents || []).map((inc) => (
              <div key={inc.incident_id} className="mt-2 text-xs bg-gray-800/40 rounded-lg px-3 py-2">
                <p>{inc.incident_id} · {inc.threat} · {inc.severity}</p>
                <p className="text-gray-500">Project {inc.project_id} · {inc.status}</p>
              </div>
            ))}
            {summary && (
              <div className="mt-3 text-sm text-gray-300">
                <p>{summary.summary}</p>
                <p className="text-xs text-gray-500 mt-1">{summary.root_cause}</p>
              </div>
            )}
            <button
              className="btn-secondary mt-3"
              type="button"
              onClick={() => downloadFile(`/advanced/reports/security/${selected}`, `advanced_security_${selected}.pdf`)}
            >
              Security report PDF
            </button>
          </div>
          <div className="card space-y-3">
            <h3 className="font-semibold">SHAP / LIME viewers</h3>
            <p className="text-sm text-gray-400">{shap?.summary}</p>
            <p className="text-sm text-gray-400">{lime?.summary}</p>
            {shap?.contributions && (
              <div className="text-xs space-y-1">
                {shap.contributions.slice(0, 6).map((c) => (
                  <div key={c.feature} className="flex justify-between">
                    <span>{c.feature}</span>
                    <span>{c.contribution}%</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
