import { Link, NavLink, Outlet } from 'react-router-dom';
import { motion } from 'framer-motion';

export const ADVANCED_LINKS = [
  { to: '/advanced/dashboard', label: 'Unified Dashboard' },
  { to: '/advanced/integration', label: 'Phase Engine' },
  { to: '/advanced/assistant', label: 'AI Assistant' },
  { to: '/advanced/compliance', label: 'Compliance' },
  { to: '/advanced/forensics', label: 'Forensics' },
];

export function AdvancedShell() {
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap gap-2">
        {ADVANCED_LINKS.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) =>
              `px-3.5 py-1.5 rounded-full text-xs font-medium border transition-colors ${
                isActive
                  ? 'bg-gradient-to-r from-primary-600/30 to-accent-600/20 text-primary-200 border-primary-500/40'
                  : 'bg-white/5 text-gray-400 border-white/10 hover:text-gray-200'
              }`
            }
          >
            {link.label}
          </NavLink>
        ))}
      </div>
      <Outlet />
    </div>
  );
}

export function Notice({ type = 'info', children }) {
  const styles = {
    info: 'bg-primary-600/10 border-primary-500/30 text-primary-300',
    error: 'bg-red-500/10 border-red-500/30 text-red-400',
    success: 'bg-green-500/10 border-green-500/30 text-green-400',
  };
  return <div className={`px-4 py-3 rounded-lg border text-sm ${styles[type]}`}>{children}</div>;
}

export function Empty({ title, text }) {
  return (
    <div className="card text-center py-10 text-sm text-gray-500">
      <p className="font-medium text-gray-300">{title}</p>
      <p className="mt-1">{text}</p>
    </div>
  );
}

export function Metric({ label, value, hint }) {
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="stat-card">
      <p className="text-gray-500 text-sm">{label}</p>
      <p className="text-2xl font-bold mt-1">{value ?? '—'}</p>
      {hint && <p className="text-xs text-gray-600 mt-1">{hint}</p>}
    </motion.div>
  );
}

export function Field({ label, children }) {
  return (
    <label className="block text-sm">
      <span className="text-gray-500 text-xs">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}

export function Back() {
  return (
    <Link to="/advanced" className="text-xs text-primary-400 hover:underline">
      All advanced features
    </Link>
  );
}
