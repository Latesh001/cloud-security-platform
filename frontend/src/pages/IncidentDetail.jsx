import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  FiArrowLeft, FiDownload, FiCheckCircle, FiZap, FiClock, FiUser, FiGlobe,
  FiMonitor, FiServer, FiShield, FiCpu, FiXCircle,
} from 'react-icons/fi';
import api, { downloadFile } from '../services/api';
import {
  Alert, Loader, PageHeader, SeverityBadge, StatusBadge, formatBytes, formatDate,
} from '../components/ui';

const TIMELINE_ICONS = {
  'Security Event Detected': FiZap,
  'AI Threat Prediction': FiCpu,
  'Incident Created': FiShield,
  'Response Executed': FiCheckCircle,
  'Evidence Stored': FiServer,
  'Notification Sent': FiMonitor,
};

export default function IncidentDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const load = useCallback(async () => {
    try {
      const { data: result } = await api.get(`/incidents/${id}`);
      setData(result);
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || 'Could not load this incident.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const runResponse = async () => {
    setBusy('respond');
    setError('');
    setNotice('');
    try {
      await api.post(`/incidents/respond/${id}`);
      await load();
      setNotice('Response playbook executed. All actions are simulated and recorded as evidence.');
    } catch (err) {
      setError(err.response?.data?.error || 'The response playbook could not be executed.');
    } finally {
      setBusy('');
    }
  };

  const closeIncident = async () => {
    setBusy('close');
    setError('');
    setNotice('');
    try {
      await api.post(`/incidents/close/${id}`);
      await load();
      setNotice('Incident closed.');
    } catch (err) {
      setError(err.response?.data?.error || 'The incident could not be closed.');
    } finally {
      setBusy('');
    }
  };

  const download = async () => {
    setBusy('download');
    setError('');
    try {
      await downloadFile(`/incidents/report/${id}`, `incident_${id}_full_report.pdf`);
    } catch {
      setError('The incident report is not available yet.');
    } finally {
      setBusy('');
    }
  };

  if (loading) return <Loader label="Loading incident..." />;
  if (error && !data) {
    return (
      <div className="space-y-4">
        <Alert type="error">{error}</Alert>
        <Link to="/incidents" className="btn-secondary inline-block">Back to Incidents</Link>
      </div>
    );
  }

  const {
    incident, project = {}, detection = {}, event = {},
    responses = [], evidence, timeline = [],
  } = data;
  const isClosed = incident.status === 'Closed';

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <PageHeader title={`Incident ${incident.incident_id}`} subtitle={incident.threat}>
        <Link to="/incidents" className="btn-secondary flex items-center gap-2">
          <FiArrowLeft /> Back
        </Link>
        <button onClick={download} disabled={busy === 'download'} className="btn-secondary flex items-center gap-2">
          <FiDownload /> {busy === 'download' ? 'Preparing...' : 'Download Report'}
        </button>
        {!isClosed && (
          <button onClick={closeIncident} disabled={busy === 'close'} className="btn-secondary flex items-center gap-2">
            <FiXCircle /> {busy === 'close' ? 'Closing...' : 'Close Incident'}
          </button>
        )}
        {incident.status === 'Open' && (
          <button onClick={runResponse} disabled={busy === 'respond'} className="btn-primary flex items-center gap-2">
            <FiZap /> {busy === 'respond' ? 'Executing...' : 'Execute Response'}
          </button>
        )}
      </PageHeader>

      {error && <Alert type="error">{error}</Alert>}
      {notice && <Alert type="success">{notice}</Alert>}

      <Alert type="info">
        Response actions in this platform are <strong>simulated</strong>. They are recorded as
        forensic evidence and shown in the timeline, but no real cloud resource is modified.
        This keeps the full SOAR workflow demonstrable while staying safe to run locally.
      </Alert>

      {/* Overview */}
      <div className="card">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-5">
          <div>
            <h3 className="font-semibold text-lg">{incident.threat}</h3>
            <p className="text-sm text-gray-500 mt-1">
              Detected on {formatDate(incident.created_time)}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-sm">
          {[
            [FiShield, 'Project', project.project_name || incident.project_id],
            [FiShield, 'Project ID', incident.project_id],
            [FiUser, 'Affected User', incident.affected_user || event.username || 'Unknown'],
            [FiGlobe, 'Source IP', incident.source_ip || event.sourceIP || 'Unknown'],
            [FiCpu, 'AI Confidence', `${incident.confidence}%`],
            [FiGlobe, 'Country', evidence?.country || event.country || 'Unknown'],
            [FiMonitor, 'Browser', evidence?.browser || event.browser || 'Unknown'],
            [FiZap, 'Trigger Event', evidence?.eventType || event.eventType || 'Unknown'],
            [FiServer, 'Resource', evidence?.resource || event.resource || 'Unknown'],
            [FiClock, 'Detected', formatDate(incident.created_time)],
            [FiClock, 'Resolved', formatDate(incident.resolved_time)],
            [FiCpu, 'Playbook', detection.playbook_name || 'Not assigned'],
          ].map(([Icon, label, value]) => (
            <div key={label} className="p-3 bg-gray-800/40 rounded-lg">
              <p className="flex items-center gap-2 text-gray-500 text-xs">
                <Icon className="shrink-0" /> {label}
              </p>
              <p className="text-gray-200 mt-1 truncate">{value || '—'}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="font-semibold mb-4">Project Context</h3>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
            {[
              ['Name', project.project_name],
              ['Category', project.category],
              ['Language', project.programming_language],
              ['Framework', project.framework],
              ['Cloud provider', project.cloud_provider],
              ['Phase 1 score', project.security_score != null ? `${project.security_score}/100` : null],
              ['Project status', project.status],
              ['Monitoring', project.monitoring_enabled ? 'Enabled' : 'Disabled'],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs text-gray-500">{label}</dt>
                <dd className="text-gray-200 mt-0.5 break-words">{value || '—'}</dd>
              </div>
            ))}
          </dl>
        </div>

        <div className="card">
          <h3 className="font-semibold mb-4">AI Detection</h3>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
            {[
              ['Model used', detection.model_used],
              ['Confidence', detection.confidence != null ? `${detection.confidence}%` : `${incident.confidence}%`],
              ['Threshold', detection.threshold != null ? `${detection.threshold}%` : '85%'],
              ['Anomaly flagged', detection.is_anomaly ? 'Yes' : 'No'],
              ['Escalated to Phase 3', detection.is_threat ? 'Yes' : 'No'],
              ['Playbook', detection.playbook_name],
              ['Playbook key', detection.playbook_key],
              ['Playbook steps', detection.playbook_steps],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs text-gray-500">{label}</dt>
                <dd className="text-gray-200 mt-0.5 break-words">{value ?? '—'}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>

      <div className="card">
        <h3 className="font-semibold mb-4">Triggering Cloud Event</h3>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-sm">
          {[
            ['Event type', event.eventType],
            ['Log source', event.logType],
            ['Result', event.status],
            ['User', event.username],
            ['Source IP', event.sourceIP],
            ['Country', event.country],
            ['Browser', event.browser],
            ['Resource', event.resource],
            ['MFA enabled', event.mfaEnabled == null ? null : (event.mfaEnabled ? 'Yes' : 'No')],
            ['Suspicious', event.isSuspicious == null ? null : (event.isSuspicious ? 'Yes' : 'No')],
            ['Bytes transferred', event.bytesTransferred != null ? formatBytes(event.bytesTransferred) : null],
            ['Event time', formatDate(event.timestamp)],
          ].map(([label, value]) => (
            <div key={label}>
              <dt className="text-xs text-gray-500">{label}</dt>
              <dd className="text-gray-200 mt-0.5 break-words">{value || '—'}</dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Timeline */}
      <div className="card">
        <h3 className="font-semibold mb-5">Incident Timeline</h3>
        {timeline.length === 0 ? (
          <p className="text-sm text-gray-500">No timeline has been recorded for this incident.</p>
        ) : (
          <div className="relative pl-8">
            <div className="absolute left-3 top-2 bottom-2 w-px bg-gray-800" />
            <div className="space-y-5">
              {timeline.map((entry, index) => {
                const Icon = TIMELINE_ICONS[entry.event] || FiClock;
                return (
                  <motion.div key={index}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: Math.min(index * 0.05, 0.5) }}
                    className="relative">
                    <div className="absolute -left-8 w-6 h-6 rounded-full bg-gray-900 border-2 border-primary-500/50 flex items-center justify-center">
                      <Icon className="text-[10px] text-primary-400" />
                    </div>
                    <p className="text-sm font-medium">{entry.event}</p>
                    <p className="text-sm text-gray-400 mt-0.5">{entry.details}</p>
                    <p className="text-xs text-gray-600 mt-0.5">{formatDate(entry.time)}</p>
                  </motion.div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Response actions */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold">Response Playbook Actions</h3>
          <span className="text-sm text-gray-500">{responses.length} step{responses.length === 1 ? '' : 's'}</span>
        </div>
        {responses.length === 0 ? (
          <p className="text-sm text-gray-500">
            No response has been executed yet. Use "Execute Response" to run the matched playbook.
          </p>
        ) : (
          <div className="space-y-2.5">
            {responses.map((response, index) => (
              <div key={index} className="flex items-center justify-between gap-4 flex-wrap p-3.5 bg-gray-800/40 rounded-lg">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="w-6 h-6 rounded-full bg-success-500/20 text-success-500 flex items-center justify-center text-xs font-semibold shrink-0">
                    {index + 1}
                  </span>
                  <span className="text-sm truncate">{response.action}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-xs text-green-400">{response.result}</span>
                  <span className="text-xs text-gray-600">{formatDate(response.executed_time)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Forensic evidence */}
      <div className="card">
        <h3 className="font-semibold mb-4">Forensic Evidence</h3>
        {!evidence ? (
          <p className="text-sm text-gray-500">
            No forensic record was stored. Evidence is written to MongoDB, so confirm MongoDB is running.
          </p>
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm mb-4">
              {[
                ['Evidence ID', evidence._id],
                ['Captured At', formatDate(evidence.timestamp)],
                ['Threat', evidence.threat],
                ['Severity', evidence.severity],
              ].map(([label, value]) => (
                <div key={label}>
                  <p className="text-gray-500 text-xs">{label}</p>
                  <p className="text-gray-200 mt-0.5 font-mono text-xs break-all">{value}</p>
                </div>
              ))}
            </div>
            <details className="group">
              <summary className="cursor-pointer text-sm text-primary-400 hover:text-primary-300 select-none">
                View raw event record
              </summary>
              <pre className="mt-3 p-4 bg-gray-950 rounded-lg text-xs text-gray-400 overflow-x-auto font-mono">
                {JSON.stringify(evidence.eventHistory ?? evidence, null, 2)}
              </pre>
            </details>
          </>
        )}
      </div>
    </div>
  );
}
