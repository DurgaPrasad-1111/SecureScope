import { FormEvent, useMemo, useState } from 'react';
import { UserPlus, ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';

import { apiRequest } from '../../api/client';
import { handleApiError } from '../../utils/errorHandler';
import { useAuth } from '../context/AuthContext';

const ROLE_OPTIONS = [
  { value: 'basic', label: 'Basic (Passive scans)' },
  { value: 'authorized', label: 'Authorized (Active scans)' },
  { value: 'admin', label: 'Admin (Full access)' },
];

export default function AdminCreateUser() {
  const { user } = useAuth();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('basic');
  const [submitting, setSubmitting] = useState(false);

  const roleLabel = useMemo(() => ROLE_OPTIONS.find((r) => r.value === role)?.label || role, [role]);

  if (user?.role !== 'admin') {
    return (
      <div className="p-8 max-w-2xl mx-auto mt-10">
        <div className="glass-surface rounded-2xl p-8 border border-red-500/30 shadow-xl shadow-red-500/10 text-center">
          <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-6">
            <ShieldAlert className="w-8 h-8 text-red-400" />
          </div>
          <h1 className="text-2xl font-bold text-slate-900 mb-2 font-display">Access Denied</h1>
          <p className="text-slate-600">Only administrators can create user accounts.</p>
        </div>
      </div>
    );
  }

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    try {
      await apiRequest('/admin/users', {
        method: 'POST',
        body: {
          username: username.trim(),
          email: email.trim(),
          password,
          roles: [role],
        },
      });
      toast.success(`User created with role: ${roleLabel}`);
      setUsername('');
      setEmail('');
      setPassword('');
      setRole('basic');
    } catch (error) {
      handleApiError(error);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-8 max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-slate-900 font-display">Create Operator Account</h1>
        <p className="text-slate-600 mt-1">Provision new users and assign their access tier.</p>
      </div>

      <div className="glass-surface rounded-3xl p-8 border border-slate-200 shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-emerald-400/10 flex items-center justify-center">
            <UserPlus className="w-5 h-5 text-emerald-700" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-900 font-display">New User Details</h2>
            <p className="text-sm text-slate-600">Passwords must be 12+ chars with upper/lower/number/special.</p>
          </div>
        </div>

        <form onSubmit={(e) => void onSubmit(e)} className="space-y-5">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-3 bg-slate-50/60 border border-slate-200 text-slate-900 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-300 focus:border-transparent placeholder-slate-500 transition-all"
              placeholder="operator_alpha"
              autoComplete="username"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 bg-slate-50/60 border border-slate-200 text-slate-900 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-300 focus:border-transparent placeholder-slate-500 transition-all"
              placeholder="operator@securescope.local"
              autoComplete="email"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Temporary Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 bg-slate-50/60 border border-slate-200 text-slate-900 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-300 focus:border-transparent placeholder-slate-500 transition-all"
              placeholder="************"
              autoComplete="new-password"
              required
              minLength={12}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full px-4 py-3 bg-slate-50/60 border border-slate-200 text-slate-900 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-300 focus:border-transparent transition-all"
            >
              {ROLE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full px-4 py-3 mt-2 rounded-xl bg-emerald-400 text-slate-950 font-semibold shadow-lg hover:shadow-emerald-400/25 disabled:opacity-60 transition-all duration-200"
          >
            {submitting ? 'Creating User...' : 'Create User'}
          </button>
        </form>
      </div>
    </div>
  );
}

