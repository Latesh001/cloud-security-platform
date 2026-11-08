import { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import api from '../services/api';

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const [status, setStatus] = useState('verifying');

  useEffect(() => {
    const token = params.get('token');
    if (token) {
      api.post('/auth/verify-email', { token })
        .then(() => setStatus('success'))
        .catch(() => setStatus('error'));
    } else {
      setStatus('error');
    }
  }, [params]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 p-4">
      <div className="card max-w-md text-center">
        {status === 'verifying' && <p className="text-gray-400">Verifying your email...</p>}
        {status === 'success' && (
          <>
            <div className="text-4xl mb-4">✅</div>
            <h2 className="text-xl font-bold text-success-500">Email Verified!</h2>
            <p className="text-gray-400 mt-2">Your account is now active.</p>
            <Link to="/login" className="btn-primary inline-block mt-6">Go to Login</Link>
          </>
        )}
        {status === 'error' && (
          <>
            <div className="text-4xl mb-4">❌</div>
            <h2 className="text-xl font-bold text-red-400">Verification Failed</h2>
            <p className="text-gray-400 mt-2">The link may be expired or invalid.</p>
            <Link to="/register" className="btn-primary inline-block mt-6">Register Again</Link>
          </>
        )}
      </div>
    </div>
  );
}
