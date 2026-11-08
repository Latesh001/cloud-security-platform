import { useState } from 'react';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';
import {
  FiUser, FiMail, FiLock, FiCheckCircle, FiAlertCircle,
} from 'react-icons/fi';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import { Alert, PageHeader } from '../components/ui';

const ROLES = [
  'Developer',
  'Security Analyst',
  'Incident Responder',
  'Student',
  'Researcher',
  'Project Manager',
];

const profileSchema = Yup.object({
  name: Yup.string().trim().min(2, 'At least 2 characters').max(150).required('Full name is required'),
  country: Yup.string().max(100),
  state: Yup.string().max(100),
  organization: Yup.string().max(150),
  profession: Yup.string().max(100),
});

const TABS = [
  { id: 'profile', label: 'Profile' },
  { id: 'security', label: 'Security' },
];

export default function Profile() {
  const { user, login } = useAuth();
  const [tab, setTab] = useState('profile');
  const [message, setMessage] = useState(null);

  const notify = (type, text) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 5000);
  };

  const persistUser = (updated) => {
    login(localStorage.getItem('token'), updated);
  };

  const saveProfile = async (values, { setSubmitting }) => {
    try {
      const { data } = await api.put('/auth/profile', values);
      persistUser(data.user);
      notify('success', 'Profile updated successfully.');
    } catch (err) {
      notify('error', err.response?.data?.error || 'Could not update your profile.');
    }
    setSubmitting(false);
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <PageHeader title="Profile and Settings" subtitle="Manage your account details and security preferences" />

      {message && <Alert type={message.type}>{message.text}</Alert>}

      {/* Identity summary */}
      <div className="card flex items-center gap-5 flex-wrap">
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center text-2xl font-bold shrink-0">
          {user?.name?.charAt(0)?.toUpperCase()}
        </div>
        <div className="min-w-0">
          <h3 className="font-semibold text-lg truncate">{user?.name}</h3>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-gray-500 mt-1">
            {user?.email && <span className="flex items-center gap-1.5"><FiMail /> {user.email}</span>}
            {user?.country && <span className="flex items-center gap-1.5">{user.country}</span>}
            <span className="flex items-center gap-1.5"><FiUser /> {user?.role}</span>
          </div>
        </div>
        <div className="ml-auto">
          <span className={`px-3 py-1 rounded-full text-xs font-medium border flex items-center gap-1.5
            ${user?.verification_status === 'verified'
              ? 'bg-green-500/15 text-green-400 border-green-500/30'
              : 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'}`}>
            {user?.verification_status === 'verified' ? <FiCheckCircle /> : <FiAlertCircle />}
            {user?.verification_status === 'verified' ? 'Verified' : 'Unverified'}
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {TABS.map(({ id, label }) => (
          <button key={id} onClick={() => setTab(id)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors
              ${tab === id ? 'bg-primary-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-gray-200'}`}>
            {label}
          </button>
        ))}
      </div>

      {tab === 'profile' && (
        <div className="card">
          <h3 className="font-semibold mb-5">Personal Information</h3>
          <Formik
            enableReinitialize
            initialValues={{
              name: user?.name || '',
              country: user?.country || '',
              state: user?.state || '',
              organization: user?.organization || '',
              profession: user?.profession || '',
              role: user?.role || 'Developer',
            }}
            validationSchema={profileSchema}
            onSubmit={saveProfile}
          >
            {({ isSubmitting }) => (
              <Form className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1.5">Full Name</label>
                  <Field name="name" className="input-field" />
                  <ErrorMessage name="name" component="p" className="text-red-400 text-xs mt-1" />
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1.5">Location</label>
                  <Field name="country" className="input-field" placeholder="City, country" />
                </div>

                <div>
                  <label className="block text-sm text-gray-400 mb-1.5">Role</label>
                  <Field as="select" name="role" className="input-field">
                    {ROLES.map((role) => (
                      <option key={role} value={role}>{role}</option>
                    ))}
                  </Field>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1.5">Organization</label>
                    <Field name="organization" className="input-field" />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1.5">Profession</label>
                    <Field name="profession" className="input-field" />
                  </div>
                </div>

                <div className="pt-2 text-xs text-gray-500">
                  Email address is the sign-in identity and cannot be changed here.
                </div>

                <button type="submit" disabled={isSubmitting} className="btn-primary">
                  {isSubmitting ? 'Saving...' : 'Save Changes'}
                </button>
              </Form>
            )}
          </Formik>
        </div>
      )}

      {tab === 'security' && (
        <div className="space-y-4">
          <div className="card">
            <h3 className="font-semibold mb-4">Account Security Overview</h3>
            <div className="space-y-3">
              {[
                ['Email sign-in', 'Registered email opens the dashboard', true],
                ['Session tokens', 'JWT with configurable expiry', true],
                ['Account verification', user?.verification_status === 'verified' ? 'Verified' : 'Pending verification',
                  user?.verification_status === 'verified'],
                ['Audit logging', 'All authentication events recorded', true],
              ].map(([label, detail, ok]) => (
                <div key={label} className="flex items-center justify-between gap-4 p-3 bg-gray-800/40 rounded-lg">
                  <div className="flex items-center gap-3 min-w-0">
                    {ok
                      ? <FiCheckCircle className="text-green-400 shrink-0" />
                      : <FiAlertCircle className="text-yellow-400 shrink-0" />}
                    <div className="min-w-0">
                      <p className="text-sm">{label}</p>
                      <p className="text-xs text-gray-500 truncate">{detail}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <FiLock className="text-primary-400" /> Security Recommendations
            </h3>
            <ul className="space-y-2 text-sm text-gray-400">
              {[
                'Sign in only with the email address you registered.',
                'Review notifications regularly for unexpected login activity.',
                'Rescan projects after every dependency upgrade.',
              ].map((tip) => (
                <li key={tip} className="flex gap-2">
                  <span className="text-primary-400 shrink-0">•</span>{tip}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
