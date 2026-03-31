import { useEffect, useState } from 'react';
import { Check, X, ShieldAlert } from 'lucide-react';

import { approveAdminRequest, rejectAdminRequest, listAdminRequests, type AdminRequest } from '../../api/adminRequests';
import { handleApiError } from '../../utils/errorHandler';
import { useAuth } from '../context/AuthContext';
import { formatSystemTime } from '../../utils/dateFormatter';

const STATUS_OPTIONS = ['pending', 'approved', 'denied'] as const;

export default function AdminRequests() {
  const { user } = useAuth();
  const [statusFilter, setStatusFilter] = useState<(typeof STATUS_OPTIONS)[number]>('pending');
  const [requests, setRequests] = useState<AdminRequest[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user?.role !== 'admin') return;
    let mounted = true;
    (async () => {
      setLoading(true);
      try {
        const data = await listAdminRequests(statusFilter);
        if (mounted) {
          // The API might return all requests, filter locally for the selected tab
          const filtered = (data.requests || []).filter(r => r.status === statusFilter);
          setRequests(filtered);
        }
      } catch (error) {
        if (mounted) {
          setRequests([]);
          handleApiError(error);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => {
      mounted = false;
    };
  }, [statusFilter, user?.role]);

  const handleDecision = async (req: AdminRequest, action: 'approve' | 'deny') => {
    try {
      if (action === 'approve') {
        await approveAdminRequest(req.id);
      } else {
        await rejectAdminRequest(req.id);
      }
      setRequests((prev) => prev.filter((item) => item.id !== req.id));
    } catch (error) {
      handleApiError(error);
    }
  };

  if (user?.role !== 'admin') {
    return (
      <div className="p-8 max-w-2xl mx-auto mt-10">
        <div className="bg-white rounded-2xl p-8 border border-red-500/30 shadow-xl shadow-red-500/10 text-center">
          <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-6">
            <ShieldAlert className="w-8 h-8 text-red-400" />
          </div>
          <h1 className="text-2xl font-bold text-slate-900 mb-2">Access Denied</h1>
          <p className="text-slate-600">Only administrators can review access requests.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="mb-8 flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">System Access Requests</h1>
          <p className="text-slate-600 mt-1">Approve or deny requests to grant platform scanner access.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 bg-white p-1 rounded-xl border border-slate-200">
          {STATUS_OPTIONS.map((status) => (
            <button
              key={status}
              type="button"
              onClick={() => setStatusFilter(status)}
              className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                statusFilter === status 
                  ? 'bg-emerald-400 text-slate-900 shadow-sm' 
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <span className="capitalize">{status}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-50/50 border-b border-slate-200">
              <tr className="text-left text-slate-600">
                <th className="py-4 px-6 font-medium">User</th>
                <th className="py-4 px-6 font-medium">Reason</th>
                <th className="py-4 px-6 font-medium">Requested</th>
                <th className="py-4 px-6 font-medium">Status</th>
                <th className="py-4 px-6 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                    <div className="flex justify-center items-center gap-2">
                       <div className="w-5 h-5 border-2 border-emerald-300 border-t-transparent animate-spin rounded-full"></div>
                       Loading requests…
                    </div>
                  </td>
                </tr>
              ) : null}
              {!loading && requests.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-slate-500">
                    No <span className="text-slate-700 font-medium">{statusFilter}</span> requests found.
                  </td>
                </tr>
              ) : null}
              {requests.map((req) => (
                <tr key={req.id} className="text-slate-700 hover:bg-white/80 transition-colors">
                  <td className="py-4 px-6">
                    <div className="font-medium text-slate-900">{req.user?.name || req.user?.username || 'Unknown'}</div>
                    <div className="text-xs text-slate-500">{req.user?.email || ''}</div>
                  </td>
                  <td className="py-4 px-6 text-slate-600 max-w-md truncate">{req.reason || '—'}</td>
                  <td className="py-4 px-6 text-slate-500">{req.createdAt ? formatSystemTime(req.createdAt) : '—'}</td>
                  <td className="py-4 px-6">
                     <span className={`px-2 py-1 rounded-md text-xs font-medium border ${
                       req.status === 'pending' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                       req.status === 'approved' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                       'bg-red-500/10 text-red-400 border-red-500/20'
                     }`}>
                       <span className="capitalize">{req.status}</span>
                     </span>
                  </td>
                  <td className="py-4 px-6 text-right flex justify-end">
                    {req.status === 'pending' ? (
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          title="Approve access"
                          onClick={() => void handleDecision(req, 'approve')}
                          className="flex items-center justify-center w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 hover:text-emerald-700 transition-colors"
                        >
                          <Check className="w-4 h-4" />
                        </button>
                        <button
                          type="button"
                          title="Deny access"
                          onClick={() => void handleDecision(req, 'deny')}
                          className="flex items-center justify-center w-8 h-8 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-colors"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-600">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}



