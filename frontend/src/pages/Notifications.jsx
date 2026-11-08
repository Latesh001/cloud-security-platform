import { useCallback, useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  FiBell, FiCheck, FiCheckCircle, FiTrash2, FiRefreshCw, FiAlertTriangle,
  FiShield, FiActivity, FiUploadCloud,
} from 'react-icons/fi';
import api from '../services/api';
import { Alert, EmptyState, Loader, PageHeader, formatDate } from '../components/ui';

/** Pick an icon and accent that matches the notification subject. */
function classify(title = '') {
  const lower = title.toLowerCase();
  if (lower.includes('threat') || lower.includes('incident')) {
    return { Icon: FiAlertTriangle, accent: 'text-red-400 bg-red-500/15' };
  }
  if (lower.includes('approved') || lower.includes('activated') || lower.includes('completed')) {
    return { Icon: FiCheckCircle, accent: 'text-green-400 bg-green-500/15' };
  }
  if (lower.includes('remediation') || lower.includes('improvement')) {
    return { Icon: FiShield, accent: 'text-orange-400 bg-orange-500/15' };
  }
  if (lower.includes('upload') || lower.includes('project')) {
    return { Icon: FiUploadCloud, accent: 'text-primary-400 bg-primary-600/15' };
  }
  if (lower.includes('login') || lower.includes('monitoring')) {
    return { Icon: FiActivity, accent: 'text-accent-400 bg-accent-600/15' };
  }
  return { Icon: FiBell, accent: 'text-gray-400 bg-gray-700/40' };
}

export default function Notifications() {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');

  const load = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true);
    try {
      const { data } = await api.get('/notifications');
      setNotifications(data.notifications || []);
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || 'Could not load notifications.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(true); }, [load]);

  const markRead = async (id) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
    try {
      await api.post(`/notifications/${id}/read`);
    } catch {
      load(false);
    }
  };

  const markAllRead = async () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    try {
      await api.post('/notifications/read-all');
    } catch {
      load(false);
    }
  };

  const remove = async (id) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
    try {
      await api.delete(`/notifications/${id}`);
    } catch {
      load(false);
    }
  };

  if (loading) return <Loader label="Loading notifications..." />;

  const unreadCount = notifications.filter((n) => !n.read).length;
  const visible = filter === 'unread' ? notifications.filter((n) => !n.read) : notifications;

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <PageHeader
        title="Notifications"
        subtitle={unreadCount > 0 ? `${unreadCount} unread` : 'You are all caught up'}
      >
        <button onClick={() => load(false)} className="btn-secondary flex items-center gap-2">
          <FiRefreshCw /> Refresh
        </button>
        {unreadCount > 0 && (
          <button onClick={markAllRead} className="btn-primary flex items-center gap-2">
            <FiCheck /> Mark All Read
          </button>
        )}
      </PageHeader>

      {error && <Alert type="error">{error}</Alert>}

      <div className="flex gap-2">
        {[['all', `All (${notifications.length})`], ['unread', `Unread (${unreadCount})`]].map(([key, label]) => (
          <button key={key} onClick={() => setFilter(key)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors
              ${filter === key ? 'bg-primary-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-gray-200'}`}>
            {label}
          </button>
        ))}
      </div>

      {visible.length === 0 ? (
        <EmptyState
          icon={FiBell}
          title={filter === 'unread' ? 'No unread notifications' : 'No notifications yet'}
          description="Notifications appear when projects are scanned, threats are detected, and incidents are resolved."
        />
      ) : (
        <div className="space-y-2.5">
          {visible.map((notification, index) => {
            const { Icon, accent } = classify(notification.title);
            return (
              <motion.div
                key={notification.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: Math.min(index * 0.03, 0.3) }}
                className={`card !p-4 flex items-start gap-4 transition-colors
                  ${notification.read ? '' : 'border-primary-500/30 bg-primary-600/5'}`}
              >
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${accent}`}>
                  <Icon />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-start gap-2">
                    <p className="font-medium text-sm">{notification.title}</p>
                    {!notification.read && (
                      <span className="w-2 h-2 rounded-full bg-primary-500 mt-1.5 shrink-0" />
                    )}
                  </div>
                  <p className="text-sm text-gray-400 mt-1">{notification.message}</p>
                  <p className="text-xs text-gray-600 mt-1.5">{formatDate(notification.date)}</p>
                </div>

                <div className="flex items-center gap-1 shrink-0">
                  {!notification.read && (
                    <button onClick={() => markRead(notification.id)}
                      className="p-2 text-gray-500 hover:text-green-400 rounded-lg hover:bg-gray-800"
                      title="Mark as read">
                      <FiCheck />
                    </button>
                  )}
                  <button onClick={() => remove(notification.id)}
                    className="p-2 text-gray-500 hover:text-red-400 rounded-lg hover:bg-gray-800"
                    title="Delete">
                    <FiTrash2 />
                  </button>
                </div>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}
