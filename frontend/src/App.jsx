import { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import Layout from './layouts/Layout';
import Login from './pages/Login';
import { AdvancedShell } from './pages/advanced/shared';

// Login is bundled eagerly because it is the first screen an unauthenticated
// visitor sees. Everything else loads on demand, so the initial download stays
// small and the chart-heavy pages only cost what they are worth when opened.
const Register = lazy(() => import('./pages/Register'));
const ForgotPassword = lazy(() => import('./pages/ForgotPassword'));
const VerifyEmail = lazy(() => import('./pages/VerifyEmail'));
const ResetPassword = lazy(() => import('./pages/ResetPassword'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Projects = lazy(() => import('./pages/Projects'));
const CreateProject = lazy(() => import('./pages/CreateProject'));
const ProjectDetail = lazy(() => import('./pages/ProjectDetail'));
const SecurityReport = lazy(() => import('./pages/SecurityReport'));
const Monitoring = lazy(() => import('./pages/Monitoring'));
const Incidents = lazy(() => import('./pages/Incidents'));
const IncidentDetail = lazy(() => import('./pages/IncidentDetail'));
const Notifications = lazy(() => import('./pages/Notifications'));
const Profile = lazy(() => import('./pages/Profile'));
const AdvancedHub = lazy(() => import('./pages/advanced/Hub'));
const UnifiedDashboard = lazy(() => import('./pages/advanced/UnifiedDashboard'));
const IntegrationEngine = lazy(() => import('./pages/advanced/IntegrationEngine'));
const Assistant = lazy(() => import('./pages/advanced/Assistant'));
const Compliance = lazy(() => import('./pages/advanced/Compliance'));
const Forensics = lazy(() => import('./pages/advanced/Forensics'));

function Spinner({ fullScreen = false }) {
  return (
    <div className={`flex items-center justify-center ${fullScreen ? 'min-h-screen' : 'h-64'}`}>
      <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500" />
    </div>
  );
}

function PrivateRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return <Spinner fullScreen />;
  return isAuthenticated ? children : <Navigate to="/login" replace />;
}

function PublicRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return null;
  return isAuthenticated ? <Navigate to="/dashboard" replace /> : children;
}

export default function App() {
  return (
    <Suspense fallback={<Spinner fullScreen />}>
      <Routes>
        <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />
        <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
        <Route path="/forgot-password" element={<PublicRoute><ForgotPassword /></PublicRoute>} />
        <Route path="/verify-email" element={<VerifyEmail />} />
        <Route path="/reset-password" element={<ResetPassword />} />

        <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="projects" element={<Projects />} />
          <Route path="projects/create" element={<CreateProject />} />
          <Route path="projects/:id" element={<ProjectDetail />} />
          <Route path="projects/:id/report" element={<SecurityReport />} />
          <Route path="monitoring" element={<Monitoring />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<IncidentDetail />} />
          <Route path="notifications" element={<Notifications />} />
          <Route path="profile" element={<Profile />} />
          <Route path="advanced" element={<AdvancedShell />}>
            <Route index element={<AdvancedHub />} />
            <Route path="dashboard" element={<UnifiedDashboard />} />
            <Route path="integration" element={<IntegrationEngine />} />
            <Route path="assistant" element={<Assistant />} />
            <Route path="siem" element={<Navigate to="/advanced" replace />} />
            <Route path="soar" element={<Navigate to="/advanced" replace />} />
            <Route path="compliance" element={<Compliance />} />
            <Route path="forensics" element={<Forensics />} />
            <Route path="intel" element={<Navigate to="/advanced" replace />} />
            <Route path="vulnerabilities" element={<Navigate to="/advanced" replace />} />
            <Route path="assets" element={<Navigate to="/advanced" replace />} />
          </Route>
        </Route>

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Suspense>
  );
}
