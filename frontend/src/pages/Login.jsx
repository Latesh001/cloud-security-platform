import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';
import { motion } from 'framer-motion';
import { FiShield, FiActivity, FiAlertTriangle, FiCheckCircle, FiLogIn } from 'react-icons/fi';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';

const schema = Yup.object({
  email: Yup.string().email('Enter a valid email address').required('Email address is required'),
});

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();
  const [error, setError] = useState('');

  const handleSubmit = async (values, { setSubmitting }) => {
    setError('');
    try {
      const res = await api.post('/auth/login', { email: values.email.trim() });
      login(res.data.access_token, res.data.user);
      navigate('/dashboard');
    } catch (err) {
      const data = err.response?.data || {};
      setError(data.error || 'Login failed');
    }
    setSubmitting(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-5xl grid lg:grid-cols-2 gap-0 overflow-hidden rounded-3xl border border-white/10 bg-slate-950/70 shadow-2xl relative z-10">
        <div className="hidden lg:flex flex-col justify-between p-10 bg-gradient-to-br from-primary-600/25 via-slate-900 to-accent-600/20 border-r border-white/10">
          <div>
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center mb-6">
              <FiShield className="text-2xl text-white" />
            </div>
            <p className="text-xs uppercase tracking-[0.2em] text-primary-300">Cloud Security Platform</p>
            <h2 className="font-display text-3xl font-bold mt-2 leading-tight">Scan. Monitor. Respond.</h2>
            <p className="text-gray-400 mt-3 text-sm leading-relaxed">
              Phase 1 static analysis, Phase 2 AI monitoring, and Phase 3 automated incident response — one reviewer-ready workspace.
            </p>
          </div>
          <div className="space-y-3 mt-8">
            {[
              { icon: FiCheckCircle, title: 'Phase 1', text: 'ZIP scan, scoring, and approval at 65/100' },
              { icon: FiActivity, title: 'Phase 2', text: 'Isolation Forest + Random Forest live monitoring' },
              { icon: FiAlertTriangle, title: 'Phase 3', text: 'Playbooks, forensics, and incident PDFs' },
            ].map((item) => (
              <div key={item.title} className="flex items-start gap-3 rounded-xl bg-white/5 border border-white/10 p-3">
                <item.icon className="text-accent-400 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-semibold">{item.title}</p>
                  <p className="text-xs text-gray-400">{item.text}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="p-8 sm:p-10">
        <div className="text-center mb-8 lg:text-left">
          <div className="w-14 h-14 mx-auto lg:mx-0 rounded-2xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center mb-4 lg:hidden">
            <FiShield className="text-2xl text-white" />
          </div>
          <h2 className="font-display text-2xl font-bold">Welcome back</h2>
          <p className="text-gray-500 mt-1">Enter your registered email to open the dashboard</p>
        </div>

        {location.state?.message && (
          <div className="mb-4 p-3 bg-success-500/10 border border-success-500/30 rounded-lg text-success-400 text-sm">
            {location.state.message}
          </div>
        )}
        {error && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
            <p>{error}</p>
          </div>
        )}

        <Formik initialValues={{ email: '' }} validationSchema={schema} onSubmit={handleSubmit}>
          {({ isSubmitting }) => (
            <Form className="space-y-4">
              <div>
                <Field name="email" type="email" placeholder="Registered email address" className="input-field" autoComplete="email" />
                <ErrorMessage name="email" component="div" className="text-red-400 text-xs mt-1" />
              </div>
              <button type="submit" disabled={isSubmitting} className="btn-primary w-full flex items-center justify-center gap-2">
                <FiLogIn /> {isSubmitting ? 'Signing in...' : 'Login'}
              </button>
            </Form>
          )}
        </Formik>

        <p className="text-center lg:text-left text-gray-500 text-sm mt-6">
          Don't have an account? <Link to="/register" className="text-primary-400 hover:underline">Register</Link>
        </p>
        </div>
      </motion.div>
    </div>
  );
}
