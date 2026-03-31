import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { AlertTriangle, ChevronRight, Clock, Package, Shield, TrendingDown, TrendingUp, Trash2, RefreshCcw } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { toast } from 'sonner';

import { getDashboardMetrics, getFindingsDistribution, getRecentScans, getRiskTrend } from '../../../api/dashboard';
import { handleApiError } from '../../../utils/errorHandler';
import { deleteScans } from '../../../api/scans';
import { formatSystemTime } from '../../../utils/dateFormatter';

function getStatusColor(status: string) {
  switch ((status || '').toLowerCase()) {
    case 'completed':
      return 'bg-emerald-100 text-emerald-700 border border-emerald-200';
    case 'in_progress':
    case 'running':
      return 'bg-blue-100 text-blue-700 border border-blue-200';
    case 'failed':
      return 'bg-red-100 text-red-700 border border-red-200';
    case 'queued':
    case 'pending':
    default:
      return 'bg-slate-100 text-slate-600 border border-slate-200';
  }
}

function getTypeColor(type: string) {
  if (type === 'quick_scan') return 'bg-orange-100 text-orange-700 border border-orange-200';
  if (type === 'normal_scan') return 'bg-sky-100 text-sky-700 border border-sky-200';
  if (type === 'full_scan') return 'bg-emerald-100 text-emerald-700 border border-emerald-200';
  return 'bg-slate-100 text-slate-600 border border-slate-200';
}

export default function ReconDashboard() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState<any>(null);
  const [riskTrend, setRiskTrend] = useState<{ dateLabel: string; score: number }[]>([]);
  const [distribution, setDistribution] = useState<{ severity: string; count: number; color: string }[]>([]);
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [clearing, setClearing] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      setLoading(true);
      try {
        const [m, trend, dist, recent] = await Promise.all([
          getDashboardMetrics(),
          getRiskTrend({ timeframe: '30d' }),
          getFindingsDistribution(),
          getRecentScans({ limit: 10, offset: 0 }),
        ]);
        if (!mounted) return;
        setMetrics(m);
        setRiskTrend(trend.data.map((p: any) => ({ dateLabel: p.dateLabel, score: p.score })));
        
        // Match Tailwind generic colors to dark mode equivalents mapping for the charts
        const darkColors: Record<string, string> = {
          '#ef4444': '#f87171', // red
          '#f97316': '#fb923c', // orange
          '#eab308': '#facc15', // yellow
          '#22c55e': '#4ade80', // green
        };
        const mappedDist = (dist.distribution || []).map((d: any) => ({ 
           ...d, 
           color: darkColors[d.color?.toLowerCase()] || '#34d399' 
        }));
        
        setDistribution(mappedDist);
        setRecentScans(recent.scans);
      } catch (error) {
        if (mounted) {
          handleApiError(error);
          setMetrics(null);
          setRiskTrend([]);
          setDistribution([]);
          setRecentScans([]);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    void load();
    const interval = window.setInterval(load, 30000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, [reloadTick]);

  const handleClearHistory = async () => {
    if (!window.confirm('Are you sure you want to strictly erase all your scan history? This action is unrecoverable.')) return;
    setClearing(true);
    try {
      const resp = await deleteScans();
      toast.success(`Removed ${resp.deleted_count} scan(s) successfully.`);
      setReloadTick(prev => prev + 1);
    } catch (e) {
      handleApiError(e);
    } finally {
      setClearing(false);
    }
  };

  const metricCards = useMemo(() => {
    const lastScanTs = metrics?.lastScan?.timestamp ? formatSystemTime(metrics.lastScan.timestamp) : 'No scans yet';
    const riskValue = typeof metrics?.riskScore?.value === 'number' ? metrics.riskScore.value.toFixed(1) : '0.0';

    return [
      {
        title: 'Total Assets',
        value: String(metrics?.totalAssets?.value ?? 0),
        change: loading ? 'Loading assets...' : metrics?.totalAssets?.change?.timeframe ?? '',
        changeType: (metrics?.totalAssets?.change?.direction ?? 'neutral') as 'increase' | 'decrease' | 'neutral',
        icon: Package,
        iconBg: 'from-sky-400 to-emerald-400',
      },
      {
        title: 'Critical Findings',
        value: String(metrics?.criticalFindings?.value ?? 0),
        change: loading ? 'Loading findings...' : metrics?.criticalFindings?.change?.timeframe ?? '',
        changeType: (metrics?.criticalFindings?.change?.direction ?? 'neutral') as 'increase' | 'decrease' | 'neutral',
        icon: AlertTriangle,
        iconBg: 'from-red-500 to-rose-600',
      },
      {
        title: 'Risk Score',
        value: `${riskValue}/10`,
        change: loading ? 'Calculating...' : metrics?.riskScore?.change?.timeframe ?? '',
        changeType: (metrics?.riskScore?.change?.direction ?? 'neutral') as 'increase' | 'decrease' | 'neutral',
        icon: Shield,
        iconBg: 'from-orange-500 to-amber-600',
      },
      {
        title: 'Last Scan',
        value: lastScanTs,
        change: metrics?.lastScan?.relativeTime || '',
        changeType: 'neutral' as const,
        icon: Clock,
        iconBg: 'from-emerald-400 to-teal-600',
      },
    ];
  }, [loading, metrics]);

  const riskScoreData = useMemo(() => riskTrend.map((p) => ({ date: p.dateLabel, score: p.score })), [riskTrend]);

  const findingsData = useMemo(
    () =>
      distribution.map((d) => ({
        name: d.severity[0].toUpperCase() + d.severity.slice(1),
        value: d.count,
        fill: d.color,
      })),
    [distribution],
  );

  return (
    <div className="p-8">
      <div className="mb-8 flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">Reconnaissance Overview</h1>
          <p className="text-slate-600 mt-1">Live view of active dashboard metrics, risk trends, and security events</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setReloadTick(prev => prev + 1)}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-100 text-slate-900 text-sm font-medium rounded-xl border border-emerald-200 hover:bg-emerald-200 transition-colors"
          >
            <RefreshCcw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Reload
          </button>
          <button
            type="button"
            onClick={() => void handleClearHistory()}
            disabled={clearing}
            className="flex items-center gap-2 px-4 py-2 bg-red-500/10 text-red-500 hover:bg-red-500/20 text-sm font-medium rounded-xl border border-red-500/20 transition-colors disabled:opacity-50"
          >
            <Trash2 className="w-4 h-4 text-red-400" />
            {clearing ? 'Clearing...' : 'Clear Scan History'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {metricCards.map((card, index) => {
          const Icon = card.icon;
          return (
            <div key={index} className="bg-white rounded-2xl p-6 shadow-sm border border-slate-200 hover:shadow-lg hover:border-slate-600 transition-all cursor-default group">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <p className="text-sm font-medium text-slate-600 mb-1">{card.title}</p>
                  <p className="text-2xl font-bold text-slate-900 group-hover:text-emerald-900 transition-colors">{card.value}</p>
                </div>
                <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${card.iconBg} flex items-center justify-center shadow-inner`}>
                  <Icon className="w-6 h-6 text-slate-900" />
                </div>
              </div>
              <div className="flex items-center gap-2 text-xs font-medium">
                {card.changeType === 'increase' && <TrendingUp className="w-4 h-4 text-emerald-400" />}
                {card.changeType === 'decrease' && <TrendingDown className="w-4 h-4 text-rose-400" />}
                <span className="text-slate-500">{card.change}</span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 mb-8">
        <div className="lg:col-span-3 bg-white rounded-2xl p-6 shadow-sm border border-slate-200">
          <div className="mb-6">
            <h3 className="text-lg font-bold text-slate-900">Risk Score Time Series</h3>
            <p className="text-sm text-slate-600">Historical asset threat profile measured over the trailing 30 days</p>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={riskScoreData} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
              <defs>
                <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#34d399" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#34d399" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
              <XAxis dataKey="date" stroke="#94a3b8" tick={{ fill: '#94a3b8' }} tickLine={false} axisLine={false} dy={10} />
              <YAxis stroke="#94a3b8" tick={{ fill: '#94a3b8' }} tickLine={false} axisLine={false} dx={-10} />
              <Tooltip 
                 contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', borderRadius: '0.5rem' }}
                 itemStyle={{ color: '#34d399', fontWeight: 'bold' }}
              />
              <Line type="monotone" dataKey="score" stroke="#34d399" strokeWidth={3} fill="url(#colorScore)" dot={{ r: 4, fill: '#34d399', strokeWidth: 0 }} activeDot={{ r: 6, strokeWidth: 0 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="lg:col-span-2 bg-white rounded-2xl p-6 shadow-sm border border-slate-200">
          <div className="mb-6">
            <h3 className="text-lg font-bold text-slate-900">Vulnerability Breakdown</h3>
            <p className="text-sm text-slate-600">Current exposed severity classifications</p>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={findingsData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
              <XAxis dataKey="name" stroke="#94a3b8" tick={{ fill: '#94a3b8' }} tickLine={false} axisLine={false} dy={10} />
              <YAxis stroke="#94a3b8" tick={{ fill: '#94a3b8' }} tickLine={false} axisLine={false} />
              <Tooltip 
                 contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', borderRadius: '0.5rem' }}
                 cursor={{ fill: 'rgba(255,255,255,0.05)' }}
              />
              <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={60}>
                {findingsData.map((entry, index) => (
                  <Cell key={`bar-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-200">
        <div className="mb-6">
          <h3 className="text-lg font-bold text-slate-900">Recent Security Scans</h3>
          <p className="text-sm text-slate-600">Chronological telemetry of executed target scans</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-200/80 bg-slate-50/30">
                <th className="text-left py-4 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider rounded-tl-lg">Scan Target</th>
                <th className="text-left py-4 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Type</th>
                <th className="text-left py-4 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Status</th>
                <th className="text-left py-4 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Findings</th>
                <th className="text-left py-4 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider">Date Evaluated</th>
                <th className="text-left py-4 px-4 text-xs font-semibold text-slate-600 uppercase tracking-wider rounded-tr-lg">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {recentScans.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-100 transition-colors">
                  <td className="py-4 px-4">
                    <span className="font-semibold text-slate-900">{scan.target}</span>
                  </td>
                  <td className="py-4 px-4">
                    <span className={`px-2.5 py-1 rounded-md text-xs font-semibold uppercase ${getTypeColor(scan.type)} shadow-sm`}>{scan.typeLabel}</span>
                  </td>
                  <td className="py-4 px-4">
                    <span className={`px-2.5 py-1 rounded-md text-xs font-semibold uppercase ${getStatusColor(scan.status || '')} shadow-sm`}>{scan.status}</span>
                  </td>
                  <td className="py-4 px-4">
                    <span className={`font-bold ${scan.findings > 4 ? 'text-rose-400' : 'text-slate-700'}`}>{scan.findings}</span>
                  </td>
                  <td className="py-4 px-4 text-sm text-slate-600 font-medium">{scan.startedAt ? formatSystemTime(scan.startedAt) : 'Unknown'}</td>
                  <td className="py-4 px-4">
                    <button type="button" onClick={() => navigate(`/scan/${scan.id}`)} className="flex items-center gap-1 text-emerald-700 hover:text-emerald-900 font-medium">
                      <span className="text-sm">Inspect Focus</span>
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && recentScans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-500 bg-slate-50/10">
                    No scan data resides in the central database.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}






