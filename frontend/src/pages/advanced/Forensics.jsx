import { useEffect, useRef, useState } from 'react';
import api, { downloadFile, downloadPost } from '../../services/api';
import { Empty, Field, Notice } from './shared';

const CUSTODY_PRESETS = [
  { action: 'Transferred to SOC analyst for review', status: 'In Review' },
  { action: 'Copied into the secure evidence locker', status: 'Sealed' },
  { action: 'Opened for forensic analysis', status: 'Analyzed' },
  { action: 'Returned to storage after analysis', status: 'Archived' },
  { action: 'Handed to incident lead', status: 'Transferred' },
];

function mergeEvidence(existing, incoming) {
  const next = Array.isArray(incoming) ? incoming : [];
  const seen = new Set();
  const out = [];
  for (const row of [...next, ...existing]) {
    const key = row?.forensic_id;
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

function EvidenceCard({
  row, draft, setDraft, onTransfer, onPdf, onCustodyFile, transferring, downloading,
}) {
  const preset = draft.preset || CUSTODY_PRESETS[0].action;
  const custom = preset === 'custom';

  return (
    <div className="card space-y-4">
      <div className="flex flex-wrap justify-between gap-2">
        <h3 className="font-semibold">{row.forensic_id} · {row.filename}</h3>
        <span className="text-xs uppercase text-gray-400">{row.status}</span>
      </div>
      <div className="bg-gray-800/60 rounded-lg px-3 py-2 space-y-2">
        <p className="text-xs text-gray-400">SHA256</p>
        <p className="text-xs font-mono break-all text-gray-100">{row.sha256}</p>
        <p className="text-xs text-gray-400 pt-1">MD5</p>
        <p className="text-xs font-mono break-all text-gray-100">{row.md5}</p>
      </div>
      <p className="text-sm text-gray-500">
        Project {row.project_id || 'Unassigned'} · Incident {row.incident_id || '—'} · {row.size} bytes
      </p>
      <div>
        <h4 className="text-sm font-medium mb-2">Chain of custody</h4>
        <div className="space-y-1 text-xs text-gray-300">
          {(row.custody || []).length === 0 && <p className="text-gray-500">No custody events yet.</p>}
          {(row.custody || []).map((c, i) => (
            <div key={i} className="bg-gray-800/40 rounded-md px-3 py-2">
              {c.time ? new Date(c.time).toLocaleString() : ''} · {c.actor} · {c.action} · {c.status}
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="Custody action (what happened to this evidence)">
          <select
            className="input-field"
            value={preset}
            onChange={(e) => setDraft({ ...draft, preset: e.target.value })}
          >
            {CUSTODY_PRESETS.map((item) => (
              <option key={item.action} value={item.action}>{item.action}</option>
            ))}
            <option value="custom">Custom action — type it below</option>
          </select>
        </Field>
        <Field label="New status">
          <select
            className="input-field"
            value={draft.status || 'In Review'}
            onChange={(e) => setDraft({ ...draft, status: e.target.value })}
          >
            <option>In Review</option>
            <option>Sealed</option>
            <option>Analyzed</option>
            <option>Transferred</option>
            <option>Archived</option>
          </select>
        </Field>
        {custom && (
          <div className="md:col-span-2">
            <Field label="Custom action">
              <input
                className="input-field"
                placeholder="Example: Handed USB image to analyst Priya for memory analysis"
                value={draft.action || ''}
                onChange={(e) => setDraft({ ...draft, action: e.target.value })}
              />
            </Field>
          </div>
        )}
        <div className="md:col-span-2">
          <Field label="Actor (who took this step — optional)">
            <input
              className="input-field"
              placeholder="Example: SOC Analyst / your name"
              value={draft.actor || ''}
              onChange={(e) => setDraft({ ...draft, actor: e.target.value })}
            />
          </Field>
          <p className="text-xs text-gray-500 mt-1">
            Record a real handling step: who received the evidence, where it was stored, or what analysis was done. Then click Add custody.
          </p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <button className="btn-secondary" type="button" disabled={!!transferring} onClick={() => onTransfer(row)}>
          {transferring ? 'Saving…' : 'Add custody'}
        </button>
        <button className="btn-secondary" type="button" disabled={!!downloading} onClick={() => onCustodyFile(row)}>
          {downloading === 'txt' ? 'Preparing…' : 'Custody file'}
        </button>
        <button className="btn-primary" type="button" disabled={!!downloading} onClick={() => onPdf(row)}>
          {downloading === 'pdf' ? 'Preparing PDF…' : 'Forensic PDF'}
        </button>
      </div>
    </div>
  );
}

export default function Forensics() {
  const [rows, setRows] = useState([]);
  const [projects, setProjects] = useState([]);
  const [error, setError] = useState('');
  const [ok, setOk] = useState('');
  const [text, setText] = useState('');
  const [file, setFile] = useState(null);
  const [projectId, setProjectId] = useState('');
  const [incidentId, setIncidentId] = useState('');
  const [busy, setBusy] = useState(false);
  const [drafts, setDrafts] = useState({});
  const [transferring, setTransferring] = useState('');
  const [downloading, setDownloading] = useState({});
  const resultRef = useRef(null);

  const load = () => {
    api.get('/advanced/forensics')
      .then((r) => {
        const reports = r.data.reports || [];
        if (reports.length) {
          setRows((prev) => mergeEvidence(prev, reports));
        }
      })
      .catch((err) => setError(err.response?.data?.error || 'Could not load forensics.'));
    api.get('/advanced/integration')
      .then((r) => setProjects(r.data.workflows || []))
      .catch(() => {});
  };

  useEffect(() => { load(); }, []);

  const hash = async (e) => {
    e.preventDefault();
    setBusy(true); setError(''); setOk('');
    try {
      let data = {};
      if (file) {
        const fd = new FormData();
        fd.append('file', file);
        if (projectId) fd.append('project_id', projectId);
        if (incidentId) fd.append('incident_id', incidentId);
        ({ data } = await api.post('/advanced/forensics/hash', fd));
      } else {
        ({ data } = await api.post('/advanced/forensics/hash', {
          content: text, filename: 'pasted.txt', project_id: projectId || undefined, incident_id: incidentId || undefined,
        }));
      }
      const record = data.record;
      const reports = data.reports;
      if (Array.isArray(reports) && reports.length) {
        setRows((prev) => mergeEvidence(prev, reports));
      } else if (record) {
        setRows((prev) => mergeEvidence(prev, [record]));
      } else {
        throw new Error('Hash generated but no evidence record was returned.');
      }
      setOk('Evidence hashed. SHA256, MD5, and chain of custody are shown below. You can add a custody step or download the Forensic PDF.');
      setText('');
      setFile(null);
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Hash generation failed.');
    } finally {
      setBusy(false);
    }
  };

  const transfer = async (row) => {
    const forensicId = row.forensic_id;
    const draft = drafts[forensicId] || {};
    const selected = CUSTODY_PRESETS.find((item) => item.action === (draft.preset || CUSTODY_PRESETS[0].action));
    const action = draft.preset === 'custom'
      ? (draft.action || '').trim()
      : (selected?.action || 'Custody transfer');
    if (!action) {
      setError('Type a custom custody action, or choose one of the listed steps.');
      return;
    }
    const status = draft.status || selected?.status || 'In Review';
    setTransferring(forensicId);
    setError('');
    try {
      const { data } = await api.post('/advanced/forensics/custody', {
        forensic_id: forensicId,
        action,
        status,
        actor: (draft.actor || '').trim() || undefined,
      });
      if (data.record) {
        setRows((prev) => prev.map((r) => (r.forensic_id === forensicId ? data.record : r)));
      }
      setOk(`Custody step added: ${action}`);
      setDrafts((prev) => ({ ...prev, [forensicId]: { preset: CUSTODY_PRESETS[0].action, status: 'In Review', action: '', actor: '' } }));
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Custody update failed.');
    } finally {
      setTransferring('');
    }
  };

  const download = async (row, kind) => {
    const fid = row.forensic_id;
    setDownloading((prev) => ({ ...prev, [fid]: kind }));
    setError('');
    try {
      if (kind === 'pdf') {
        try {
          await downloadFile(`/advanced/forensics/${encodeURIComponent(fid)}/report`, `${fid}.pdf`);
        } catch {
          await downloadPost('/advanced/forensics/pdf', { forensic_id: fid }, `${fid}.pdf`);
        }
        setOk('Forensic PDF downloaded.');
      } else {
        try {
          await downloadFile(`/advanced/forensics/custody-file?forensic_id=${encodeURIComponent(fid)}`, `${fid}_custody.txt`);
        } catch {
          await downloadFile(`/advanced/forensics/${encodeURIComponent(fid)}/custody.txt`, `${fid}_custody.txt`);
        }
        setOk('Chain of custody file downloaded.');
      }
    } catch (err) {
      setError(err.message || (kind === 'pdf' ? 'Forensic PDF could not be generated.' : 'Custody file could not be downloaded.'));
    } finally {
      setDownloading((prev) => ({ ...prev, [fid]: '' }));
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Digital Forensics</h1>
        <p className="text-gray-500">
          Hash evidence, then use the card below to log a custody action or download the Forensic PDF.
        </p>
      </div>
      {error && <Notice type="error">{error}</Notice>}
      {ok && <Notice type="success">{ok}</Notice>}

      <form className="card grid grid-cols-1 md:grid-cols-2 gap-3" onSubmit={hash}>
        <Field label="Related project">
          <select className="input-field" value={projectId} onChange={(e) => setProjectId(e.target.value)}>
            <option value="">Unassigned</option>
            {projects.map((p) => <option key={p.project_id} value={p.project_id}>{p.project_id} · {p.project_name}</option>)}
          </select>
        </Field>
        <Field label="Incident ID">
          <input className="input-field" value={incidentId} onChange={(e) => setIncidentId(e.target.value)} placeholder="Optional, e.g. INC-0004" />
        </Field>
        <div className="md:col-span-2">
          <Field label="Upload log / evidence file">
            <input className="input-field" type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
          </Field>
        </div>
        <div className="md:col-span-2">
          <Field label="Or paste content to hash (log lines, email, or file text)">
            <textarea
              className="input-field min-h-[100px]"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste the evidence text here, then click Generate SHA256 + MD5."
            />
          </Field>
        </div>
        <button className="btn-primary w-fit" disabled={busy || (!file && !text)} type="submit">
          {busy ? 'Hashing…' : 'Generate SHA256 + MD5'}
        </button>
      </form>

      <div ref={resultRef}>
        <h2 className="text-lg font-semibold mb-3">Hashed evidence and chain of custody</h2>
        {rows.length === 0 ? (
          <Empty title="No evidence yet" text="Generate SHA256 + MD5 above. The hashes, custody log, and Forensic PDF button will show here." />
        ) : rows.map((row) => (
          <div key={row.forensic_id} className="mb-4">
            <EvidenceCard
              row={row}
              draft={drafts[row.forensic_id] || { preset: CUSTODY_PRESETS[0].action, status: 'In Review' }}
              setDraft={(next) => setDrafts((prev) => ({ ...prev, [row.forensic_id]: next }))}
              onTransfer={transfer}
              onPdf={(item) => download(item, 'pdf')}
              onCustodyFile={(item) => download(item, 'txt')}
              transferring={transferring === row.forensic_id}
              downloading={downloading[row.forensic_id]}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
