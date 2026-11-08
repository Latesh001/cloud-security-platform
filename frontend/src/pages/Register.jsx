import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';
import { motion } from 'framer-motion';
import { FiShield } from 'react-icons/fi';
import api from '../services/api';

export const ROLES = [
  'Developer',
  'Security Analyst',
  'Incident Responder',
  'Student',
  'Researcher',
  'Project Manager',
];

const schema = Yup.object({
  name: Yup.string().trim().required('User name is required'),
  email: Yup.string().email('Enter a valid email address').required('Email address is required'),
  location: Yup.string().trim().required('Location is required'),
  role: Yup.string().required('Role is required'),
});

export default function Register() {
  const navigate = useNavigate();
  const [error, setError] = useState('');

  const handleSubmit = async (values, { setSubmitting }) => {
    setError('');
    try {
      const res = await api.post('/auth/register', {
        name: values.name.trim(),
        email: values.email.trim(),
        location: values.location.trim(),
        role: values.role,
      });
      navigate('/login', {
        state: {
          message: res.data.message
            || 'Registration successful. Check your email, then sign in with your email address.',
        },
      });
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed');
    }
    setSubmitting(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-primary-600/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-accent-500/10 rounded-full blur-3xl" />
      </div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-lg card relative z-10">
        <div className="text-center mb-8">
          <div className="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center mb-4">
            <FiShield className="text-3xl text-white" />
          </div>
          <h2 className="font-display text-2xl font-bold">Create Account</h2>
          <p className="text-gray-500 mt-1">Join the Cloud Security Platform</p>
        </div>

        {error && <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">{error}</div>}

        <Formik
          initialValues={{ name: '', email: '', location: '', role: 'Developer' }}
          validationSchema={schema}
          onSubmit={handleSubmit}
        >
          {({ isSubmitting }) => (
            <Form className="space-y-4">
              <div>
                <Field name="name" placeholder="User name" className="input-field" autoComplete="name" />
                <ErrorMessage name="name" component="div" className="text-red-400 text-xs mt-1" />
              </div>
              <div>
                <Field name="email" type="email" placeholder="Email address" className="input-field" autoComplete="email" />
                <ErrorMessage name="email" component="div" className="text-red-400 text-xs mt-1" />
              </div>
              <div>
                <Field name="location" placeholder="Location (city, country)" className="input-field" autoComplete="address-level2" />
                <ErrorMessage name="location" component="div" className="text-red-400 text-xs mt-1" />
              </div>
              <div>
                <Field as="select" name="role" className="input-field">
                  {ROLES.map((role) => (
                    <option key={role} value={role}>{role}</option>
                  ))}
                </Field>
                <ErrorMessage name="role" component="div" className="text-red-400 text-xs mt-1" />
              </div>

              <p className="text-xs text-gray-500">
                After you register, a welcome message is sent to this email. Sign in with the same address to open the dashboard.
              </p>

              <button type="submit" disabled={isSubmitting} className="btn-primary w-full">
                {isSubmitting ? 'Creating Account...' : 'Register'}
              </button>
            </Form>
          )}
        </Formik>

        <p className="text-center text-gray-500 text-sm mt-6">
          Already have an account? <Link to="/login" className="text-primary-400 hover:underline">Login</Link>
        </p>
      </motion.div>
    </div>
  );
}
