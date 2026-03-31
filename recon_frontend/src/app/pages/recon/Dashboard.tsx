import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { RefreshCcw, EyeOff, Eye, Lock } from 'lucide-react';

import { getRecentScans, getRiskScore, getScanTimeline, getSubdomainMap, type RecentScansResponse, type RiskScoreResponse, type ScanTimelineResponse, type SubdomainMapResponse } from '../../../api/dashboard';
import { createAdminRequest, getMyAdminRequests, type AdminRequest } from '../../../api/adminRequests';
import { handleApiError } from '../../../utils/errorHandler';
import { formatSystemTime } from '../../../utils/dateFormatter';
import RiskScoreCard from '../../components/dashboard/RiskScoreCard';
import SubdomainGraph from '../../components/dashboard/SubdomainGraph';
import ScanTimeline from '../../components/dashboard/ScanTimeline';
import { useAuth } from '../../context/AuthContext';

export default function Dashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);
  const [showTimeline, setShowTimeline] = useState(true);
  const [adminRequest, setAdminRequest] = useState<AdminRequest | null>(null);
  const [adminReason, setAdminReason] = useState('');
  const [adminSubmitting, setAdminSubmitting] = useState(false);

  const [recentScans, setRecentScans] = useState<RecentScansResponse['scans']>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');

  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);
  const [subdomainMap, setSubdomainMap] = useState<SubdomainMapResponse | null>(null);
  const [scanTimeline, setScanTimeline] = useState<ScanTimelineResponse | null>(null);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      setLoadingScans(true);
      try {
        const recent = await getRecentScans({ limit: 25, offset: 0 });
        if (!mounted) return;
        setRecentScans(recent.scans || []);
        if (recent.scans?.length) {
          setSelectedScanId((prev) => prev || String(recent.scans[0].id));
        }
      } catch (error) {
        if (mounted) {
          handleApiError(error);
          setRecentScans([]);
        }
      } finally {
        if (mounted) setLoadingScans(false);
      }
    };

    void load();
    return () => {
      mounted = false;
    };
  }, [reloadTick]);

  useEffect(() => {
    if (user?.role === 'admin') return;
    let mounted = true;
    (async () => {
      try {
        const data = await getMyAdminRequests();
        if (mounted) {
          const latest = (data.requests || [])[0] || null;
          setAdminRequest(latest);
        }
      } catch (error) {
        if (mounted) handleApiError(error);
      }
    })();
    return () => {
      mounted = false;
    };
  }, [reloadTick, user?.role]);

  const submitAdminRequest = async () => {
    setAdminSubmitting(true);
    try {
      const data = await createAdminRequest(adminReason.trim());
      setAdminRequest(data.request);
      setAdminReason('');
    } catch (error) {
      handleApiError(error);
    } finally {
      setAdminSubmitting(false);
    }
  };

  useEffect(() => {
    let mounted = true;
    if (!selectedScanId) return () => {};

    const loadDetails = async () => {
      setLoadingDetails(true);
      try {
        const scanId = selectedScanId;
        const [risk, graph, timeline] = await Promise.all([
          getRiskScore({ scanId }),
          getSubdomainMap({ scanId }),
          getScanTimeline({ scanId }),
        ]);
        if (!mounted) return;
        
        if (graph && (graph as any).status === 'unavailable') {
          setSubdomainMap(null);
        } else {
          setSubdomainMap(graph);
        }
        setRiskScore(risk);
        setScanTimeline(timeline);
      } catch (error) {
        if (mounted) {
          const errMsg = String(error);
          if (!errMsg.toLowerCase().includes('subdomain')) {
            handleApiError(error);
          }
          setRiskScore(null);
          setSubdomainMap(null);
          setScanTimeline(null);
        }
      } finally {
        if (mounted) setLoadingDetails(false);
      }
    };

    void loadDetails();
    return () => {
      mounted = false;
    };
  }, [selectedScanId, reloadTick]);

  const selectedScan = useMemo(() => recentScans.find((s) => String(s.id) === String(selectedScanId)) || null, [recentScans, selectedScanId]);

  if (!user?.role) {
    return (
      <div className="p-8 max-w-3xl mx-auto mt-10">
        <div className="bg-white rounded-2xl p-8 border border-slate-200 shadow-xl text-center">
          <div className="w-16 h-16 bg-slate-200 rounded-full flex items-center justify-center mx-auto mb-6 shadow-inner">
            <Lock className="w-8 h-8 text-emerald-700" />
          </div>
          <h2 className="text-2xl font-bold text-slate-900 mb-2">Account Pending Verification</h2>
          <p className="text-slate-600 mb-8">Your account has been created successfully, but requires administrator approval before you can access the scanning engine.</p>
          
          <div className="max-w-md mx-auto text-left">
            <label className="block text-sm font-medium text-slate-700 mb-2">Request Access Reason (Optional)</label>
            <textarea
              rows={3}
              value={adminReason}
              onChange={(e) => setAdminReason(e.target.value)}
              placeholder="Tell the admin why you need access to SecureScope."
              className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-emerald-300 disabled:opacity-50 resize-none"
              disabled={adminRequest?.status === 'pending'}
            />
            
            <div className="mt-6 flex flex-col items-center">
               <button
                type="button"
                onClick={() => void submitAdminRequest()}
                disabled={adminSubmitting || adminRequest?.status === 'pending' || adminRequest?.status === 'approved'}
                className="w-full py-3 rounded-xl bg-emerald-400 text-slate-900 font-medium hover:shadow-lg hover:shadow-emerald-400/20 disabled:opacity-50 transition-all"
              >
                {adminSubmitting ? 'Submitting...' : adminRequest?.status === 'pending' ? 'Request Pending...' : adminRequest?.status === 'approved' ? 'Approved! Please log out and back in' : 'Request Access'}
              </button>
              {adminRequest?.status && (
                <p className="mt-4 text-sm text-slate-600">Current Status: <span className="text-emerald-700 capitalize font-medium">{adminRequest.status}</span></p>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">Attack Surface Dashboard</h1>
          <p className="text-slate-600 mt-1">Risk score, subdomain relationships, and scan execution timeline</p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {user?.role === 'admin' ? (
            <button
              type="button"
              onClick={() => navigate('/admin/users/new')}
              className="flex items-center gap-2 px-3 py-2 text-sm rounded-xl bg-emerald-400 text-slate-950 hover:bg-emerald-500 transition-colors"
            >
              Create User
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => setReloadTick((prev) => prev + 1)}
            className="flex items-center gap-2 px-3 py-2 text-sm rounded-xl border border-emerald-200 bg-emerald-100 text-slate-900 hover:bg-emerald-200 transition-colors"
          >
            <RefreshCcw className="w-4 h-4" />
            Reload
          </button>
          <button
            type="button"
            onClick={() => setShowTimeline((prev) => !prev)}
            className="flex items-center gap-2 px-3 py-2 text-sm rounded-xl border border-emerald-200 bg-emerald-100 text-slate-900 hover:bg-emerald-200 transition-colors"
          >
            {showTimeline ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {showTimeline ? 'Hide timeline' : 'Show timeline'}
          </button>
          <div className="text-sm text-slate-600">
            {loadingScans ? 'Loading scans...' : recentScans.length ? `${recentScans.length} recent scans` : 'No scans available'}
          </div>
          <select
            className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:ring-2 focus:ring-emerald-300 focus:outline-none"
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            disabled={!recentScans.length}
          >
            {recentScans.map((scan) => (
              <option key={scan.id} value={String(scan.id)}>
                #{scan.id} · {scan.target} · {scan.typeLabel} · {scan.status}
              </option>
            ))}
          </select>
        </div>
      </div>

      {!loadingScans && !recentScans.length ? (
        <div className="bg-white rounded-2xl p-8 shadow-sm text-center border border-slate-200">
          <div className="text-lg font-semibold text-slate-900">No scan data yet</div>
          <div className="mt-2 text-sm text-slate-600">Run a scan first, then come back to visualize risk score and relationships.</div>
        </div>
      ) : (
        <div className="space-y-6">
          {user?.role !== 'admin' ? (
            <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-200">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="text-lg font-semibold text-slate-900">Admin Access</h3>
                  <p className="text-sm text-slate-600">Request elevated privileges if you need full active scans.</p>
                </div>
                {adminRequest?.status ? (
                  <span className="text-xs px-3 py-1 rounded-full border border-slate-200 bg-slate-200 text-slate-700 capitalize">
                    {adminRequest.status}
                  </span>
                ) : null}
              </div>
              <textarea
                rows={3}
                value={adminReason}
                onChange={(e) => setAdminReason(e.target.value)}
                placeholder="Tell the admin why you need admin access (optional)."
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-emerald-300 disabled:opacity-50 resize-none"
                disabled={adminRequest?.status === 'pending'}
              />
              <div className="mt-3 flex items-center justify-between text-xs text-slate-600">
                <span>
                  {adminRequest?.status === 'pending'
                    ? 'Your request is pending review.'
                    : adminRequest?.status === 'approved'
                    ? 'Your request was approved. Log out and sign in again to refresh permissions.'
                    : adminRequest?.status === 'rejected'
                    ? 'Your request was rejected. You can submit a new request.'
                    : 'No admin request submitted yet.'}
                </span>
                <button
                  type="button"
                  onClick={() => void submitAdminRequest()}
                  disabled={adminSubmitting || adminRequest?.status === 'pending'}
                  className="text-xs px-4 py-2 rounded-xl bg-emerald-400 text-slate-950 hover:bg-emerald-300 disabled:opacity-50 transition-colors"
                >
                  {adminSubmitting ? 'Submitting...' : 'Request admin access'}
                </button>
              </div>
            </div>
          ) : null}

          <RiskScoreCard data={riskScore} loading={loadingDetails} />
          <SubdomainGraph data={subdomainMap} loading={loadingDetails} />
          {showTimeline ? <ScanTimeline data={scanTimeline} loading={loadingDetails} /> : null}

          <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-200">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-slate-900">Recent Scans</h3>
                <p className="text-sm text-slate-600">Latest scan activity</p>
              </div>
            </div>
            {!recentScans.length ? (
              <div className="text-sm text-slate-600">No recent scans available.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="text-left text-slate-600 border-b border-slate-200">
                      <th className="py-3 pr-4 font-medium">Target</th>
                      <th className="py-3 pr-4 font-medium">Type</th>
                      <th className="py-3 pr-4 font-medium">Status</th>
                      <th className="py-3 pr-4 font-medium">Findings</th>
                      <th className="py-3 pr-4 font-medium">Started</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/50">
                    {recentScans.slice(0, 10).map((scan) => (
                      <tr key={scan.id} className="text-slate-700">
                        <td className="py-3 pr-4 font-medium text-slate-900">{scan.target}</td>
                        <td className="py-3 pr-4">{scan.typeLabel}</td>
                        <td className="py-3 pr-4">
                            <span className="px-2 py-1 rounded-md text-xs bg-slate-50/50 border border-slate-200">{scan.status}</span>
                        </td>
                        <td className="py-3 pr-4">{scan.findings}</td>
                        <td className="py-3 pr-4 text-slate-600">{scan.startedAt ? formatSystemTime(scan.startedAt) : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {selectedScan ? (
            <div className="text-xs text-slate-500">
              Viewing scan #{selectedScan.id} · target <span className="font-medium text-slate-700">{selectedScan.target}</span> · status{' '}
              <span className="font-medium text-slate-700">{selectedScan.status}</span>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}







