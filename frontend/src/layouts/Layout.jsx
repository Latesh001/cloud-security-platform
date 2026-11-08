import { Outlet, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  FiHome, FiFolder, FiShield, FiActivity, FiAlertTriangle,
  FiBell, FiUser, FiLogOut, FiMenu, FiX, FiLayers
} from 'react-icons/fi';
import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import Chatbot from '../components/Chatbot';

const navItems = [
  { to: '/dashboard', icon: FiHome, label: 'Dashboard' },
  { to: '/projects', icon: FiFolder, label: 'Projects' },
  { to: '/monitoring', icon: FiActivity, label: 'Monitoring' },
  { to: '/incidents', icon: FiAlertTriangle, label: 'Incidents' },
  { to: '/advanced', icon: FiLayers, label: 'Advanced Features' },
  { to: '/notifications', icon: FiBell, label: 'Notifications' },
  { to: '/profile', icon: FiUser, label: 'Profile' },
];

const phaseLinks = [
  { to: '/dashboard', label: 'Home' },
  { to: '/projects', label: 'Phase 1' },
  { to: '/monitoring', label: 'Phase 2' },
  { to: '/incidents', label: 'Phase 3' },
  { to: '/advanced', label: 'Advanced Features' },
];

const UNREAD_POLL_MS = 30000;

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const [healthy, setHealthy] = useState(true);

  // The badge refreshes on navigation and on a timer so alerts raised by the
  // background monitoring thread surface without a manual page reload.
  useEffect(() => {
    let active = true;
    const refresh = () => {
      api.get('/notifications?unread=true')
        .then(r => { if (active) { setUnread(r.data.unread_count || 0); setHealthy(true); } })
        .catch(() => { if (active) setHealthy(false); });
    };
    refresh();
    const timer = setInterval(refresh, UNREAD_POLL_MS);
    return () => { active = false; clearInterval(timer); };
  }, [location.pathname]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className={`fixed lg:static inset-y-0 left-0 z-40 w-64 glass transform transition-transform duration-300
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}>
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center shadow-lg shadow-primary-600/30">
              <FiShield className="text-white text-xl" />
            </div>
            <div>
              <h1 className="font-display font-bold text-sm leading-tight">Cloud Security</h1>
              <p className="text-xs text-gray-500">AI Incident Response</p>
            </div>
          </div>
        </div>

        <nav className="p-4 space-y-1">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to} onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all duration-200
                ${isActive
                  ? 'bg-gradient-to-r from-primary-600/25 to-accent-600/10 text-primary-200 border border-primary-500/30 shadow-sm shadow-primary-900/40'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`
              }>
              <Icon className="text-lg" />
              {label}
              {to === '/notifications' && unread > 0 && (
                <span className="ml-auto px-2 py-0.5 rounded-full bg-danger-600 text-white text-[10px] font-bold">
                  {unread > 99 ? '99+' : unread}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-white/10">
          <div className="flex items-center gap-3 mb-3 px-2">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center text-xs font-bold">
              {user?.name?.charAt(0)?.toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{user?.name}</p>
              <p className="text-xs text-gray-500 truncate">{user?.role}</p>
            </div>
          </div>
          <button onClick={handleLogout}
            className="flex items-center gap-2 w-full px-4 py-2 text-sm text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-xl transition-colors">
            <FiLogOut /> Logout
          </button>
        </div>
      </aside>

      {/* Overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 bg-black/50 z-30 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* Main content */}
      <div className="flex-1 flex flex-col min-h-screen">
        <header className="glass sticky top-0 z-20 px-6 py-3.5 flex items-center justify-between border-b border-white/10">
          <button className="lg:hidden text-gray-400" onClick={() => setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen ? <FiX size={24} /> : <FiMenu size={24} />}
          </button>
          <nav className="hidden md:flex items-center gap-1 overflow-x-auto">
            {phaseLinks.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                className={({ isActive }) =>
                  `px-3 py-1.5 rounded-full text-xs font-medium whitespace-nowrap ${
                    isActive ? 'bg-primary-600/25 text-primary-200 border border-primary-500/30' : 'text-gray-400 hover:text-gray-200'
                  }`
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
          <div className="flex items-center gap-3">
            <NavLink to="/notifications" className="relative text-gray-400 hover:text-primary-400 transition-colors">
              <FiBell size={20} />
              {unread > 0 && (
                <span className="absolute -top-1.5 -right-1.5 min-w-[16px] h-4 px-1 rounded-full bg-danger-600 text-white text-[10px] font-bold flex items-center justify-center">
                  {unread > 9 ? '9+' : unread}
                </span>
              )}
            </NavLink>
            <span className={`px-3 py-1 text-xs rounded-full border ${healthy
              ? 'bg-success-500/20 text-success-500 border-success-500/30'
              : 'bg-danger-500/20 text-danger-500 border-danger-500/30'}`}>
              {healthy ? 'System Online' : 'Backend Unreachable'}
            </span>
          </div>
        </header>

        <main className="flex-1 p-6 overflow-auto bg-transparent">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <Outlet />
          </motion.div>
        </main>
      </div>

      <Chatbot />
    </div>
  );
}
