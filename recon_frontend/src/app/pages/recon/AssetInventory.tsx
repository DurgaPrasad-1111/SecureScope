import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import { Download, Eye, Globe, Package, Play, RefreshCcw, Search, ShieldAlert, Loader2 } from 'lucide-react';

import { exportAssets, getAssetStats, getAssets } from '../../../api/assets';
import { handleApiError } from '../../../utils/errorHandler';
import { formatSystemTime } from '../../../utils/dateFormatter';

type AssetRow = {
  id: string;
  asset: string;
  typeLabel: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | string;
  findings: number;
  lastScanLabel: string;
  status: 'active' | 'inactive' | string;
  scanId: string;
};

function filenameFromContentDisposition(value: string | null) {
  if (!value) return null;
  const match = /filename=\"?([^\";]+)\"?/i.exec(value);
  return match?.[1] || null;
}

export default function AssetInventory() {
  const navigate = useNavigate();
  const [activeFilter, setActiveFilter] = useState<'all' | 'domains'>('all');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const data = await getAssetStats();
        if (mounted) setStats(data);
      } catch (error) {
        if (mounted) handleApiError(error);
      }
    })();
    return () => {
      mounted = false;
    };
  }, [reloadTick]);

  useEffect(() => {
    let mounted = true;

    (async () => {
      setLoading(true);
      try {
        const data = await getAssets({
          page: 1,
          limit: 100,
          filter: activeFilter,
          search: search.trim() || undefined,
          sortBy: 'lastScan',
          sortOrder: 'desc',
        });

        if (!mounted) return;
        setAssets(
          data.assets.map((a) => ({
            id: a.id,
            asset: a.asset,
            typeLabel: a.typeLabel,
            riskLevel: a.riskLevel,
            findings: a.findings,
            lastScanLabel: a.lastScan?.timestamp ? formatSystemTime(a.lastScan.timestamp) : a.lastScan?.relativeTime || '—',
            status: a.status,
            scanId: a.lastScan?.scanId || '',
          })),
        );
      } catch (error) {
        if (mounted) {
          handleApiError(error);
          setAssets([]);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    })();

    return () => {
      mounted = false;
    };
  }, [activeFilter, search, reloadTick]);

  const filters = useMemo(
    () => [
      { id: 'all' as const, label: 'All Assets', count: stats?.total ?? assets.length, icon: Package },
      { id: 'domains' as const, label: 'Domains', count: stats?.byType?.domains ?? 0, icon: Globe },
    ],
    [assets.length, stats],
  );

  const summaryCards = useMemo(
    () => [
      { label: 'Total Assets', value: String(stats?.total ?? 0), className: 'text-emerald-700' },
      { label: 'Active', value: String(stats?.active ?? 0), className: 'text-emerald-400' },
      { label: 'Inactive', value: String(stats?.inactive ?? 0), className: 'text-slate-600' },
      { label: 'At Risk', value: String(stats?.atRisk ?? 0), className: 'text-red-400' },
    ],
    [stats],
  );

  const filteredAssets = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return assets;
    return assets.filter((a) => a.asset.toLowerCase().includes(q));
  }, [assets, search]);

  const getTypeIcon = () => ({ icon: Globe, color: 'bg-emerald-300/10 text-emerald-700 border border-emerald-300/30' });

  const getRiskColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'critical': return 'text-red-500';
      case 'high': return 'text-orange-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-emerald-500';
      default: return 'text-slate-500';
    }
  };

  const getRiskDot = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'critical': return 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]';
      case 'high': return 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.6)]';
      case 'medium': return 'bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.6)]';
      case 'low': return 'bg-emerald-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]';
      default: return 'bg-slate-500';
    }
  };

  const onExport = async () => {
    try {
      const response = await exportAssets({ format: 'csv', filter: activeFilter });
      const blob = await response.blob();
      const filename = filenameFromContentDisposition(response.headers.get('content-disposition')) || 'assets-export.csv';

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      handleApiError(error);
    }
  };

  return (
    <div className="p-8">
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between mb-8 gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">Asset Inventory</h1>
          <p className="text-slate-600 mt-1">Discovered targets and their latest evaluated security posture</p>
        </div>
        <div className="flex flex-wrap items-center gap-3 w-full lg:w-auto mt-4 lg:mt-0">
          <div className="relative flex-1 lg:flex-none">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
            <input
              type="text"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              className="w-full lg:w-64 pl-9 pr-4 py-2 border border-slate-200 bg-slate-50/50 text-slate-900 rounded-xl focus:outline-none focus:ring-2 focus:ring-emerald-300 placeholder-slate-500"
              placeholder="Search target assets…"
            />
          </div>
          <button
            type="button"
            onClick={() => setReloadTick((prev) => prev + 1)}
            className="flex items-center justify-center gap-2 px-4 py-2 bg-emerald-100 text-slate-900 text-sm font-medium rounded-xl border border-emerald-200 hover:bg-emerald-200 transition-colors"
          >
            <RefreshCcw className="w-4 h-4" />
            <span className="hidden sm:inline">Reload</span>
          </button>
          <button type="button" onClick={() => void onExport()} className="flex items-center justify-center gap-2 px-4 py-2 bg-emerald-400 text-slate-900 text-sm font-medium rounded-xl hover:shadow-lg hover:shadow-emerald-400/20 transition-all">
            <Download className="w-4 h-4" />
            <span className="hidden sm:inline">Export CSV</span>
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-8 pb-2">
        {filters.map((filter) => {
          const Icon = filter.icon;
          const selected = activeFilter === filter.id;
          return (
            <button
              key={filter.id}
              type="button"
              onClick={() => setActiveFilter(filter.id)}
              className={`
                flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all border
                ${selected ? 'bg-emerald-300/10 text-emerald-700 border-emerald-300/40' : 'bg-white text-slate-600 border-slate-200 hover:text-slate-900 hover:bg-slate-100'}
              `}
            >
              <Icon className="w-4 h-4" />
              <span>{filter.label}</span>
              <span className={`
                px-2 py-0.5 rounded-full text-xs font-bold
                ${selected ? 'bg-emerald-400 text-slate-950' : 'bg-slate-50 border border-slate-600 text-slate-700'}
              `}>
                {filter.count}
              </span>
            </button>
          );
        })}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        {summaryCards.map((stat, index) => (
          <div key={index} className="bg-white rounded-2xl p-5 shadow-sm border border-slate-200 flex flex-col items-start">
            <p className="text-sm font-medium text-slate-600 mb-2 uppercase tracking-wide">{stat.label}</p>
            <p className={`text-3xl font-bold ${stat.className}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="bg-white rounded-2xl shadow-sm overflow-hidden border border-slate-200">
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-slate-50/40 border-b border-slate-200/80">
              <tr>
                <th className="text-left py-4 px-6 text-xs font-semibold text-slate-600 uppercase tracking-wider rounded-tl-lg">Target Name</th>
                <th className="text-left py-4 px-6 text-xs font-semibold text-slate-600 uppercase tracking-wider">Classification</th>
                <th className="text-left py-4 px-6 text-xs font-semibold text-slate-600 uppercase tracking-wider">Risk Level</th>
                <th className="text-left py-4 px-6 text-xs font-semibold text-slate-600 uppercase tracking-wider">Findings</th>
                <th className="text-left py-4 px-6 text-xs font-semibold text-slate-600 uppercase tracking-wider">Last Sync</th>
                <th className="text-left py-4 px-6 text-xs font-semibold text-slate-600 uppercase tracking-wider">Posture</th>
                <th className="text-left py-4 px-6 text-xs font-semibold text-slate-600 uppercase tracking-wider rounded-tr-lg">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-sm text-slate-500">
                     <div className="flex flex-col items-center justify-center">
                       <Loader2 className="w-8 h-8 text-emerald-700 animate-spin mb-3" />
                       Loading recognized assets…
                     </div>
                  </td>
                </tr>
              ) : null}
              {!loading ? (
                filteredAssets.map((asset) => {
                  const typeInfo = getTypeIcon();
                  const TypeIcon = typeInfo.icon;

                  return (
                    <tr key={asset.id} className="hover:bg-slate-100 transition-colors">
                      <td className="py-4 px-6">
                        <span className="font-semibold text-slate-900 tracking-wide">{asset.asset}</span>
                      </td>
                      <td className="py-4 px-6">
                        <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold uppercase ${typeInfo.color}`}>
                          <TypeIcon className="w-3.5 h-3.5" />
                          <span>{asset.typeLabel}</span>
                        </div>
                      </td>
                      <td className="py-4 px-6">
                        <div className="flex items-center gap-2">
                          <div className={`w-2.5 h-2.5 rounded-full ${getRiskDot(asset.riskLevel)}`}></div>
                          <span className={`font-semibold uppercase tracking-wider text-xs ${getRiskColor(asset.riskLevel)}`}>{asset.riskLevel}</span>
                        </div>
                      </td>
                      <td className="py-4 px-6">
                        <span className={`font-bold ${asset.findings > 0 ? 'text-slate-900' : 'text-slate-500'}`}>{asset.findings}</span>
                      </td>
                      <td className="py-4 px-6 text-sm font-medium text-slate-600">{asset.lastScanLabel}</td>
                      <td className="py-4 px-6">
                        <span className={`px-2.5 py-1 rounded-md text-xs font-bold uppercase border ${asset.status === 'active' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-slate-500/10 text-slate-600 border-slate-500/20'}`}>
                          {asset.status}
                        </span>
                      </td>
                      <td className="py-4 px-6">
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            title="Execute New Scan"
                            onClick={() => navigate(`/new-scan?target=${encodeURIComponent(asset.asset)}`)}
                            className="p-1.5 text-emerald-700 hover:text-emerald-900 hover:bg-slate-100 rounded-lg transition-colors border border-transparent hover:border-slate-600"
                          >
                            <Play className="w-4 h-4" />
                          </button>
                          <button
                            type="button"
                            title="View Last Report"
                            disabled={!asset.scanId}
                            onClick={() => navigate(`/scan/${asset.scanId}`)}
                            className="p-1.5 text-emerald-400 hover:text-emerald-700 hover:bg-slate-100 rounded-lg transition-colors disabled:opacity-30 disabled:hover:bg-transparent border border-transparent hover:border-slate-600"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : null}

              {!loading && filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center text-sm text-slate-500 bg-slate-50/10">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <ShieldAlert className="h-8 w-8 text-slate-600 mb-2" />
                      No assets currently correspond to selected filters.
                    </div>
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




