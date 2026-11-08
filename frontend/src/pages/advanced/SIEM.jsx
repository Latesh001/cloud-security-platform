import { useEffect, useState } from 'react';
import api from '../../services/api';
import { Empty, Field, Notice } from './shared';

const SOURCES = ['application', 'authentication', 'network', 'cloud'];

export default function SIEM() {
  const [logs, setLogs] = useState([]);
  const [events, setEvents] = useState([]);
  const [projects, setProjects] = useState([]);
  const [q, setQ] = useState('');
  const [source, setSource] = useState('');
  const [severity, setSeverity] = useState('');
  const [error, setError] = useState('');
  const [ok, setOk] = useState('');
  const [form, setForm] = useState({
    source: 'application',
    message: '',
    severity: 'medium',
    project_id: '',
    source_ip: '',
  });

  const load = () => {
    const params = {};
    if (q) params.q = q;
    if (source) params.source = source;
    if (severity) params.severity = severity;
    api.get('/advanced/siem/logs', { params })
      .then((r) => setLogs(r.data.logs || []))
      .catch((err) => setError(err.response?.data?.error || 'Could not load SIEM logs.'));
    api.get('/advanced/siem/events')
      .then((r) => setEvents(r.data.events || []))
      .catch(() => {});
    api.get('/advanced/integration')
      .then((r) => setProjects(r.data.workflows || []))
      .catch(() => {});
  };

  useEffect(() => { load(); }, []);

  const ingest = async (e) => {
    e.preventDefault();
    setError(''); setOk('');
    try {
      const { data } = await api.post('/advanced/siem/log', form);
      if (data.log) setLogs((prev) => [data.log, ...prev]);
      if (data.event) setEvents((prev) => [data.event, ...prev]);
      setOk('Log ingested. Normalized and correlated records are shown in the panels below.');
      setForm({ ...form, message: '', source_ip: '' });
      load();
    } catch (err) {
      setError(err.response?.data?.error || 'Ingest failed.');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">SIEM Module</h1>
        <p className="text-gray-500">
          Click <strong className="text-gray-300">Ingest log</strong>. The new row appears under Normalized logs and Correlated events on this page.
        </p>
      </div>
      {error && <Notice type="error">{error}</Notice>}
      {ok && <Notice type="success">{ok}</Notice>}

      <form className="card grid grid-cols-1 md:grid-cols-2 gap-3" onSubmit={ingest}>
        <Field label="Source">
          <select className="input-field" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })}>
            {SOURCES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Severity">
          <select className="input-field" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            {['low', 'medium', 'high', 'critical'].map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Related project">
          <select className="input-field" value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })}>
            <option value="">First project / unassigned</option>
            {projects.map((p) => (
              <option key={p.project_id} value={p.project_id}>{p.project_id} · {p.project_name}</option>
            ))}
          </select>
        </Field>
        <Field label="Source IP">
          <input className="input-field" value={form.source_ip} onChange={(e) => setForm({ ...form, source_ip: e.target.value })} placeholder="Optional" />
        </Field>
        <div className="md:col-span-2">
          <Field label="Message">
            <input className="input-field" required value={form.message} onChange={(e) => setForm({ ...form, message: e.target.value })} placeholder="e.g. failed login for admin" />
          </Field>
        </div>
        <button className="btn-primary w-fit" type="submit">Ingest log</button>
      </form>

      <div className="flex flex-wrap gap-2">
        <input className="input-field" placeholder="Search logs" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input-field w-40" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="">All sources</option>
          {SOURCES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="input-field w-40" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {['low', 'medium', 'high', 'critical'].map((s) => <option key={s}>{s}</option>)}
        </select>
        <button className="btn-secondary" type="button" onClick={load}>Filter</button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="font-semibold mb-3">Normalized logs ({logs.length})</h3>
          {logs.length === 0 ? <Empty title="No logs yet" text="Ingest a log above. It will appear in this list." /> : (
            <div className="space-y-2 max-h-96 overflow-y-auto text-sm">
              {logs.map((l, i) => (
                <div key={l._id || `${l.timestamp}-${i}`} className="bg-gray-800/40 rounded-lg px-3 py-2">
                  <div className="flex justify-between gap-2">
                    <span>{l.source || 'log'} · {l.project_id || '—'}</span>
                    <span className="uppercase text-xs">{l.severity}</span>
                  </div>
                  <p className="text-gray-300 mt-1">{l.message || l.event_type || 'Normalized event'}</p>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="card">
          <h3 className="font-semibold mb-3">Correlated events ({events.length})</h3>
          {events.length === 0 ? <Empty title="No correlations yet" text="Ingest a log above. A correlated event is created for every ingest." /> : (
            <div className="space-y-2 max-h-96 overflow-y-auto text-sm">
              {events.map((e, i) => (
                <div key={e._id || `${e.created_at}-${i}`} className="bg-gray-800/40 rounded-lg px-3 py-2">
                  <p className="font-medium">{e.title || e.rule || 'Correlation'}</p>
                  <p className="text-gray-400">{e.narrative || e.description || e.message}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
