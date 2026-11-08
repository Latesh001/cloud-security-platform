import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { motion } from 'framer-motion';
import api from '../services/api';

export default function ForgotPassword() {
  const [sent, setSent] = useState(false);
  const [error, setError] = useState('');

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="w-full max-w-md card">
        <h2 className="text-2xl font-bold mb-2">Reset Password</h2>
        <p className="text-gray-500 mb-6">Enter your email to receive a reset link</p>

        {sent ? (
          <div className="p-4 bg-success-500/10 border border-success-500/30 rounded-lg text-success-400">
            If the email exists, a reset link has been sent. Check your inbox.
          </div>
        ) : (
          <Formik initialValues={{ email: '' }}
            validationSchema={Yup.object({ email: Yup.string().email().required() })}
            onSubmit={async (values, { setSubmitting }) => {
              try {
                await api.post('/auth/forgot-password', values);
                setSent(true);
              } catch (err) {
                setError(err.response?.data?.error || 'Failed');
              }
              setSubmitting(false);
            }}>
            {({ isSubmitting }) => (
              <Form className="space-y-4">
                {error && <div className="text-red-400 text-sm">{error}</div>}
                <Field name="email" type="email" placeholder="Email Address" className="input-field" />
                <button type="submit" disabled={isSubmitting} className="btn-primary w-full">Send Reset Link</button>
              </Form>
            )}
          </Formik>
        )}
        <Link to="/login" className="block text-center text-primary-400 text-sm mt-4 hover:underline">Back to Login</Link>
      </motion.div>
    </div>
  );
}
