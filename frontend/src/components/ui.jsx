import { motion } from 'framer-motion';
import { FiInbox } from 'react-icons/fi';

export const SEVERITY_STYLES = {
  Critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  High: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  Medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  Low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  Normal: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
};

export const SEVERITY_COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#f59e0b',
  Low: '#3b82f6',
};

export const STATUS_STYLES = {
  Created: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
  Uploaded: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  Scanning: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  Approved: 'bg-green-500/15 text-green-400 border-green-500/30',
  'Monitoring Enabled': 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  'Pending Remediation': 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  'Incident Detected': 'bg-red-500/15 text-red-400 border-red-500/30',
  'Upload Failed': 'bg-red-500/15 text-red-400 border-red-500/30',
  Completed: 'bg-green-500/15 text-green-400 border-green-500/30',
  Open: 'bg-red-500/15 text-red-400 border-red-500/30',
  'In Progress': 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  Resolved: 'bg-green-500/15 text-green-400 border-green-500/30',
  Closed: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
  Running: 'bg-green-500/15 text-green-400 border-green-500/30',
  Stopped: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
  Validated: 'bg-red-500/15 text-red-400 border-red-500/30',
  Observation: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
};

export function Badge({ children, className = '' }) {
  return (
    <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${className}`}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }) {
  return <Badge className={SEVERITY_STYLES[severity] || SEVERITY_STYLES.Normal}>{severity}</Badge>;
}

export function StatusBadge({ status }) {
  return <Badge className={STATUS_STYLES[status] || STATUS_STYLES.Created}>{status}</Badge>;
}

export function Loader({ label = 'Loading...' }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3">
      <div className="animate-spin rounded-full h-10 w-10 border-2 border-gray-700 border-t-primary-500" />
      <p className="text-sm text-gray-500">{label}</p>
    </div>
  );
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="page-hero">
      <div>
        <h1 className="font-display text-2xl font-bold">{title}</h1>
        {subtitle && <p className="text-gray-400 mt-1">{subtitle}</p>}
      </div>
      {children && <div className="flex items-center gap-3 flex-wrap">{children}</div>}
    </div>
  );
}

export function EmptyState({ icon: Icon = FiInbox, title, description, action }) {
  return (
    <div className="card text-center py-14">
      <Icon className="text-4xl text-gray-600 mx-auto mb-3" />
      <p className="font-medium text-gray-300">{title}</p>
      {description && <p className="text-sm text-gray-500 mt-1 max-w-md mx-auto">{description}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function StatCard({ icon: Icon, label, value, color = 'bg-primary-600', delay = 0, hint }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.3 }}
      className="stat-card"
    >
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="text-gray-500 text-sm">{label}</p>
          <p className="text-3xl font-bold mt-1">{value}</p>
          {hint && <p className="text-xs text-gray-600 mt-1 truncate">{hint}</p>}
        </div>
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${color}`}>
          <Icon className="text-xl text-white" />
        </div>
      </div>
    </motion.div>
  );
}

export function ScoreRing({ score, size = 140 }) {
  const safeScore = Math.max(0, Math.min(100, Number(score) || 0));
  const radius = size / 2 - 12;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (safeScore / 100) * circumference;
  const color = safeScore >= 80 ? '#22c55e' : safeScore >= 65 ? '#f59e0b' : '#ef4444';

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} stroke="#1f2937" strokeWidth="10" fill="none" />
        <motion.circle
          cx={size / 2} cy={size / 2} r={radius}
          stroke={color} strokeWidth="10" fill="none" strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1, ease: 'easeOut' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold" style={{ color }}>{safeScore}</span>
        <span className="text-xs text-gray-500">of 100</span>
      </div>
    </div>
  );
}

export function Alert({ type = 'info', children }) {
  const styles = {
    info: 'bg-primary-600/10 border-primary-500/30 text-primary-300',
    success: 'bg-green-500/10 border-green-500/30 text-green-400',
    warning: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
    error: 'bg-red-500/10 border-red-500/30 text-red-400',
  };
  return (
    <div className={`px-4 py-3 rounded-lg border text-sm ${styles[type]}`}>{children}</div>
  );
}

export function formatDate(value) {
  if (!value) return '—';
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? '—' : value.toLocaleString();
  }
  let raw = String(value).trim();
  const hasZone = /[zZ]$/.test(raw) || /[+-]\d{2}:?\d{2}$/.test(raw);
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(raw) && !hasZone) {
    raw = `${raw.replace(' ', 'T')}Z`;
  }
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

export function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.floor(Math.log(value) / Math.log(1024));
  return `${(value / 1024 ** index).toFixed(1)} ${units[index]}`;
}
