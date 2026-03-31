import { FormEvent, useState } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { Shield, Lock } from 'lucide-react';

import { handleApiError } from '../../utils/errorHandler';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation() as any;
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    try {
      await login(email.trim(), password);
      const from = location?.state?.from;
      navigate(typeof from === 'string' && from.startsWith('/app') ? from : '/app', { replace: true });
    } catch (error) {
      handleApiError(error);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen aurora-bg flex flex-col items-center justify-center p-6 text-slate-900">
      <div className="absolute inset-0 grid-overlay"></div>
      <div className="relative w-full max-w-md">
        <div className="flex flex-col items-center mb-10 stagger-fade">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-300 via-teal-400 to-sky-500 flex items-center justify-center shadow-lg glow-ring">
            <Shield className="w-8 h-8 text-slate-950" />
          </div>
          <h1 className="text-3xl font-bold text-slate-900 font-display mt-4">SecureScope</h1>
          <p className="text-xs uppercase tracking-[0.3em] text-slate-600 font-semibold mt-2">Operator Access</p>
        </div>

        <div className="glass-surface rounded-3xl p-8 border border-slate-200 shadow-2xl">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 rounded-xl bg-emerald-100 flex items-center justify-center">
              <Lock className="w-5 h-5 text-emerald-700" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-slate-900 font-display">Welcome Back</h2>
              <p className="text-sm text-slate-600">Sign in with your platform credentials.</p>
            </div>
          </div>

          <form onSubmit={(e) => void onSubmit(e)} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Email Address</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 bg-white border border-slate-200 text-slate-900 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:border-transparent placeholder-slate-500 transition-all"
                placeholder="operator@securescope.local"
                autoComplete="email"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 bg-white border border-slate-200 text-slate-900 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:border-transparent placeholder-slate-500 transition-all"
                placeholder="************"
                autoComplete="current-password"
                required
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full px-4 py-3 mt-4 rounded-xl bg-emerald-400 text-slate-950 font-semibold shadow-lg hover:shadow-emerald-200/40 disabled:opacity-60 transition-all duration-200"
            >
              {submitting ? 'Authenticating...' : 'Authenticate Workflow'}
            </button>
          </form>

          <div className="mt-8 text-sm text-center text-slate-600 border-t border-white/10 pt-6">
            Establishing a new presence?{' '}
            <button type="button" onClick={() => navigate('/signup')} className="text-emerald-700 hover:text-emerald-900 font-semibold transition-colors">
              Request Platform Access
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

