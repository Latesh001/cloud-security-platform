import { useEffect, useState } from 'react';
import api from '../../services/api';
import { Field, Notice } from './shared';

const FALLBACK_PLAYBOOKS = [
  {
    playbook_id: 'PB-BRUTE',
    name: 'Brute Force Response',
    trigger: 'Repeated ConsoleLoginFailure',
    condition: 'failed_logins >= 5 OR threat == Brute Force',
    action: 'Lock account, record source IP, notify user',
    description: 'Stops password-spray and brute-force campaigns against console logins.',
    status: 'Ready',
  },
  {
    playbook_id: 'PB-MALWARE',
    name: 'Malware Isolation',
    trigger: 'Malware Activity or suspicious process',
    condition: 'severity in [High, Critical]',
    action: 'Quarantine resource, save forensic evidence',
    description: 'Isolates a host when malware or a suspicious process is confirmed.',
    status: 'Ready',
  },
  {
    playbook_id: 'PB-IP',
    name: 'IP Blocking',
    trigger: 'High-risk source IP or IOC match',
    condition: 'source_ip in IOC or high-risk country + no MFA',
    action: 'Block source IP at the edge (simulated)',
    description: 'Blocks a high-risk or IOC-matched source IP at the perimeter.',
    status: 'Ready',
  },
  {
    playbook_id: 'PB-USER',
    name: 'User Disable',
    trigger: 'Credential theft or insider threat',
    condition: 'threat in [Credential Theft, Insider Threat]',
    action: 'Disable user, revoke sessions, force password reset',
    description: 'Disables a compromised identity and forces credential rotation.',
    status: 'Ready',
  },
  {
    playbook_id: 'PB-EMAIL',
    name: 'Email Notification',
    trigger: 'Any Phase 3 incident',
    condition: 'incident created',
    action: 'Notify project owner and SOC analyst',
    description: 'Sends an incident notification to the project owner and SOC inbox.',
    status: 'Ready',
  },
];

export default function SOAR() {
  const [playbooks, setPlaybooks] = useState(FALLBACK_PLAYBOOKS);
  const [history, setHistory] = useState([]);
  const [projects, setProjects] = useState([]);
  const [error, setError] = useState('');
  const [ok, setOk] = useState('');
  const [busy, setBusy] = useState('');
  const [projectId, setProjectId] = useState('');

  const loadExtras = () => {
    api.get('/advanced/playbooks')
      .then((r) => {
        const incoming = r.data.playbooks || [];
        const byId = Object.fromEntries(FALLBACK_PLAYBOOKS.map((p) => [p.playbook_id, { ...p }]));
        incoming.forEach((p) => {
          const id = p.playbook_id || p.id;
          if (id) byId[id] = { ...byId[id], ...p, playbook_id: id };
        });
        setPlaybooks(Object.values(byId));
      })
      .catch(() => {});
    api.get('/advanced/playbooks/history')
      .then((r) => setHistory(r.data.history || []))
      .catch(() => {});
    api.get('/advanced/integration')
      .then((r) => setProjects(r.data.workflows || []))
      .catch(() => {});
  };

  useEffect(() => { loadExtras(); }, []);

  const run = async (playbookId) => {
    setBusy(playbookId); setError(''); setOk('');
    try {
      const selected = playbooks.find((p) => p.playbook_id === playbookId) || {};
      const { data } = await api.post('/advanced/playbook/execute', {
        playbook_id: playbookId || selected.playbook_id,
        name: selected.name,
        trigger: selected.trigger,
        condition: selected.condition,
        action: selected.action,
        project_id: projectId || undefined,
      });
      setOk(`${data.playbook_name || playbookId} executed in ${data.execution_time_ms || 0} ms.`);
      loadExtras();
    } catch (err) {
      setError(err.response?.data?.error || 'Execution failed. Restart the Flask backend and try again.');
    } finally {
      setBusy('');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">SOAR Automation Studio</h1>
        <p className="text-gray-500">
          Click <strong className="text-gray-300">Execute</strong> on a playbook card. The project dropdown is optional and is not a run control.
        </p>
      </div>
      {error && <Notice type="error">{error}</Notice>}
      {ok && <Notice type="success">{ok}</Notice>}

      <div className="max-w-md">
        <Field label="Related project (optional — not required to execute)">
          <select className="input-field" value={projectId} onChange={(e) => setProjectId(e.target.value)}>
            <option value="">None — playbook only</option>
            {projects.map((p) => (
              <option key={p.project_id} value={p.project_id}>
                {p.project_id} · {p.project_name}
              </option>
            ))}
          </select>
        </Field>
      </div>

      <h2 className="text-lg font-semibold">Playbooks</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {playbooks.map((p) => (
          <div key={p.playbook_id} className="card space-y-3">
            <div className="flex justify-between items-start gap-3">
              <h3 className="font-semibold">{p.name}</h3>
              <span className="text-xs uppercase text-gray-400">{p.status || 'ready'}</span>
            </div>
            <p className="text-sm text-gray-400">{p.description}</p>
            <p className="text-xs text-gray-500">Trigger: {p.trigger}</p>
            <p className="text-xs text-gray-500">Condition: {p.condition}</p>
            <p className="text-xs text-gray-500">Action: {p.action}</p>
            <button
              type="button"
              className="btn-primary w-full"
              disabled={busy === p.playbook_id}
              onClick={() => run(p.playbook_id)}
            >
              {busy === p.playbook_id ? 'Executing…' : `Execute ${p.name}`}
            </button>
          </div>
        ))}
      </div>

      <div className="card">
        <h3 className="font-semibold mb-3">Execution history</h3>
        {history.length === 0 ? <p className="text-sm text-gray-500">No executions yet. Use Execute on a playbook above.</p> : (
          <div className="space-y-2 text-sm">
            {history.map((h) => (
              <div key={h.history_id || h.run_id || h._id} className="flex justify-between bg-gray-800/40 rounded-lg px-3 py-2">
                <span>{h.playbook_name || h.playbook_id} · {h.status}</span>
                <span className="text-gray-500">{h.execution_time_ms || 0} ms · {h.created_at ? new Date(h.created_at).toLocaleString() : ''}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
