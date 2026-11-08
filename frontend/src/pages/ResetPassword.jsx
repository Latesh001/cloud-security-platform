import { useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import api from '../services/api';

export default function ResetPassword() {
  const [params] = useSearchParams();
  const [done, setDone] = useState(false);
  const token = params.get('token');

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-md card">
        <h2 className="text-2xl font-bold mb-6">Set New Password</h2>
        {done ? (
          <div>
            <p className="text-success-400 mb-4">Password reset successful!</p>
            <Link to="/login" className="btn-primary inline-block">Login</Link>
          </div>
        ) : (
          <Formik initialValues={{ password: '', confirm_password: '' }}
            validationSchema={Yup.object({
              password: Yup.string().min(8).required(),
              confirm_password: Yup.string().oneOf([Yup.ref('password')]).required(),
            })}
            onSubmit={async (values, { setSubmitting }) => {
              await api.post('/auth/reset-password', { ...values, token });
              setDone(true);
              setSubmitting(false);
            }}>
            {({ isSubmitting }) => (
              <Form className="space-y-4">
                <Field name="password" type="password" placeholder="New Password" className="input-field" />
                <Field name="confirm_password" type="password" placeholder="Confirm Password" className="input-field" />
                <button type="submit" disabled={isSubmitting} className="btn-primary w-full">Reset Password</button>
              </Form>
            )}
          </Formik>
        )}
      </div>
    </div>
  );
}
