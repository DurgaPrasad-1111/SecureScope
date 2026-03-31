import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router';
import { AlertTriangle, Clock, Download, Globe, Loader2, RefreshCcw, Shield } from 'lucide-react';

import { Finding, getFindingsByScanId } from '../../../api/findings';
import { getScanById, ScanDetailsResponse } from '../../../api/scans';
import { apiDownload } from '../../../api/client';
import { handleApiError } from '../../../utils/errorHandler';
import { formatSystemTime } from '../../../utils/dateFormatter';

function statusColor(status: string) {
  switch ((status || '').toLowerCase()) {
    case 'completed':
      return 'bg-emerald-100 text-emerald-700 border border-emerald-200';
    case 'in_progress':
      return 'bg-blue-100 text-blue-700 border border-blue-200';
    case 'failed':
      return 'bg-red-100 text-red-700 border border-red-200';
    case 'queued':
    case 'pending':
    default:
      return 'bg-slate-100 text-slate-600 border border-slate-200';
  }
}

function severityBadge(severity: string) {
  const value = (severity || '').toLowerCase();
  switch (value) {
    case 'critical':
      return 'bg-red-100 text-red-700 border border-red-200';
    case 'high':
      return 'bg-orange-100 text-orange-700 border border-orange-200';
    case 'medium':
      return 'bg-yellow-100 text-yellow-700 border border-yellow-200';
    case 'low':
      return 'bg-emerald-100 text-emerald-700 border border-emerald-200';
    default:
      return 'bg-slate-100 text-slate-600 border border-slate-200';
  }
}

export default function ScanResults() {
  const { id } = useParams();
  const scanId = String(id || '');
  const [scan, setScan] = useState<ScanDetailsResponse | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadTick, setReloadTick] = useState(0);
  const [elapsedSeconds, setElapsedSeconds] = useState<number | null>(null);
  const [evidenceOpen, setEvidenceOpen] = useState<Record<string, boolean>>({});

  const isInProgress = useMemo(() => {
    const status = (scan?.status || '').toLowerCase();
    return ['queued', 'pending', 'in_progress', 'running'].includes(status);
  }, [scan?.status]);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    setError(null);
    setFindingsLoading(true);
    setFindingsError(null);
    setFindings([]);

    (async () => {
      const [scanResult, findingsResult] = await Promise.allSettled([
        getScanById(scanId),
        getFindingsByScanId(scanId, { limit: 100 }),
      ]);

      if (!mounted) return;

      if (scanResult.status === 'fulfilled') {
        setScan(scanResult.value);
      } else {
        setError('Failed to fetch scan details');
        handleApiError(scanResult.reason);
      }

      if (findingsResult.status === 'fulfilled') {
        const rawFindings = Array.isArray(findingsResult.value?.findings) ? findingsResult.value.findings : [];
        const filtered = rawFindings.filter((finding) => String(finding?.scan?.id || '') === scanId);
        setFindings(filtered.length ? filtered : rawFindings);
      } else {
        setFindingsError('Failed to fetch scan findings');
        handleApiError(findingsResult.reason);
      }

      setLoading(false);
      setFindingsLoading(false);
    })();

    return () => {
      mounted = false;
    };
  }, [scanId, reloadTick]);

  useEffect(() => {
    if (!isInProgress) return;
    const id = window.setInterval(() => setReloadTick((prev) => prev + 1), 4000);
    return () => window.clearInterval(id);
  }, [isInProgress]);

  useEffect(() => {
    if (!scan?.startedAt) {
      setElapsedSeconds(null);
      return;
    }
    const updateElapsed = () => {
      const started = new Date(scan.startedAt || '').getTime();
      if (Number.isNaN(started)) return;
      const ended = scan.completedAt ? new Date(scan.completedAt).getTime() : Date.now();
      const seconds = Math.max(0, Math.round((ended - started) / 1000));
      setElapsedSeconds(seconds);
    };
    updateElapsed();
    const id = window.setInterval(updateElapsed, 1000);
    return () => window.clearInterval(id);
  }, [scan?.startedAt, scan?.completedAt]);

  const durationSeconds = useMemo(() => {
    if (typeof scan?.duration === 'number' && Number.isFinite(scan.duration)) {
      return Math.max(0, Math.round(scan.duration));
    }
    return elapsedSeconds;
  }, [scan?.duration, elapsedSeconds]);

  const durationLabel = useMemo(() => {
    if (durationSeconds == null) return '-';
    if (durationSeconds < 60) return `${durationSeconds} sec`;
    const minutes = Math.round(durationSeconds / 60);
    return `${minutes} min`;
  }, [durationSeconds]);

  const toggleEvidence = (idValue: string) =>
    setEvidenceOpen((prev) => ({ ...prev, [idValue]: !prev[idValue] }));

  const normalizeFinding = (item: any): any => {
    if (!item) return null;
    if (typeof item !== 'object') return null;

    // Helper to extract string from potential object or string
    const toString = (val: any): string => {
      if (val === null || val === undefined) return '';
      if (typeof val === 'string') return val;
      if (typeof val === 'object') {
        return val.name || val.id || val.label || JSON.stringify(val);
      }
      return String(val);
    };

    return {
      id: toString(item.id || item.title || `vuln-${Math.random()}`),
      title: toString(item.title || item.name || 'Vulnerability'),
      severity: toString(item.severity || item.risk || item.level || 'low').toLowerCase(),
      description: toString(item.description || item.details || item.info || 'No description provided.'),
      category: toString(item.category || ''),
      asset: toString(item.asset || item.asset_name || item.hostname || item.target || 'N/A'),
      discoveredAt: item.discovered_at || item.discoveredAt || item.created_at || item.timestamp || null,
      raw_output: item.raw_output || item.raw_evidence || item.raw_code || item.raw_data || '',
      mitigation: toString(item.mitigation || item.fix || item.recommendation || 'No mitigation provided.'),
    };
  };

  const vulnerabilityFindings = useMemo(() => {
    const raw = (scan as any)?.raw;
    const vulnModule = raw?.modules?.vulnerability_surface;
    let results: any[] = [];
    
    if (vulnModule?.data?.detailed_risks?.length) {
      results = vulnModule.data.detailed_risks;
    } else if (vulnModule?.data?.risks?.length) {
      results = vulnModule.data.risks;
    } else if (findings && findings.length > 0) {
      results = findings;
    }
    
    const normalized = results.map(normalizeFinding).filter(Boolean);
    return normalized;
  }, [findings, scan]);

  const displayedFindings = vulnerabilityFindings;

  const totalVulnerabilities = displayedFindings.length;

  const reportOverview = [
    { label: 'Risk Status', value: displayedFindings.some((f: any) => (f.severity || '').toLowerCase() === 'critical') ? 'CRITICAL' : (displayedFindings.length > 0 ? 'WARNING' : 'SECURE') },
    { label: 'Total Findings', value: String(totalVulnerabilities) },
    { label: 'Scan Target', value: scan?.target || 'Unknown' },
    { label: 'Scan Type', value: (scan?.scanType || 'unknown').replace('_', ' ') }
  ];

  const detailedRisks = useMemo(() => {
    const raw = (scan as any)?.raw;
    const fromRaw = raw?.modules?.vulnerability_surface?.data?.detailed_risks;
    const fromResults = (scan as any)?.results?.modules?.vulnerability_surface?.data?.detailed_risks;
    const fromRisks = raw?.modules?.vulnerability_surface?.data?.risks;
    let results: any[] = [];
    if (Array.isArray(fromRaw) && fromRaw.length > 0) results = fromRaw;
    else if (Array.isArray(fromResults) && fromResults.length > 0) results = fromResults;
    else if (Array.isArray(fromRisks) && fromRisks.length > 0) results = fromRisks;
    return results.map(normalizeFinding).filter(Boolean);
  }, [scan]);

  const downloadReport = async () => {
    if (!scan) return;
    try {
      const response = await apiDownload(`/scans/${scan.id}/raw`);
      const blob = await response.blob();
      const jsonData = JSON.parse(await blob.text());
      const reportJson = JSON.stringify(jsonData.results || jsonData, null, 2);
      const reportBlob = new Blob([reportJson], { type: 'application/json' });
      const filename = `scan-${scan.id}-report.json`;
      const url = URL.createObjectURL(reportBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      handleApiError(error);
    }
  };

  const downloadPdfReport = async () => {
    if (!scan) return;
    try {
      const response = await apiDownload(`/dashboard/report/pdf/${scan.id}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `scan-${scan.id}-report.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      handleApiError(error);
    }
  };

  if (loading) {
    return <div className="p-8 text-slate-600 flex items-center gap-2"><Loader2 className="animate-spin w-5 h-5"/> Loading scan...</div>;
  }

  if (error || !scan) {
    return <div className="p-8 text-red-500">{error || 'Scan not found'}</div>;
  }

  return (
    <div className="p-4 sm:p-8">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-8 gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 mb-2">Scan Result Details</h1>
          <p className="text-slate-600 flex items-center gap-2 flex-wrap">
            <span>Target: <strong className="text-slate-900">{scan.target}</strong></span> |
            <span>Type: <strong className="text-slate-900 capitalize">{scan.scanType.replace('_', ' ')}</strong></span> |
            Status: <span className={`px-2 py-0.5 rounded-md text-xs font-semibold ${statusColor(scan.status)} uppercase`}>{scan.status}</span>
          </p>
          <p className="text-xs text-slate-500 mt-1">
            {isInProgress ? 'Auto-refreshing while the scan runs.' : durationSeconds != null ? `Completed in ${durationSeconds} seconds.` : 'Scan completed.'}
          </p>
        </div>
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <button
            type="button"
            onClick={() => setReloadTick((prev) => prev + 1)}
            className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-emerald-200 bg-emerald-50 hover:bg-emerald-100 text-emerald-800 text-sm font-medium transition-colors cursor-pointer"
          >
            <RefreshCcw className="w-4 h-4" />
            Reload
          </button>
          <button
            type="button"
            onClick={() => void downloadPdfReport()}
            className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-sm font-medium transition-colors cursor-pointer"
          >
            <Download className="w-4 h-4" />
            PDF
          </button>
          <button
            type="button"
            onClick={() => void downloadReport()}
            className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-400 text-slate-950 text-sm font-semibold hover:bg-emerald-500 transition-all cursor-pointer"
          >
            <Download className="w-4 h-4" />
            JSON
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm">
          <p className="text-sm font-medium text-slate-600 mb-1">Progress</p>
          <div className="flex flex-col">
            <p className="text-2xl font-bold text-slate-900 flex items-center gap-2">
              {scan.progress}%
              {isInProgress ? <Loader2 className="w-5 h-5 text-emerald-600 animate-spin" /> : null}
            </p>
            {scan.currentPhase && (
              <p className="text-xs font-medium text-emerald-600 mt-1 uppercase tracking-wider">
                {scan.currentPhase.replace('_', ' ')}
              </p>
            )}
          </div>
        </div>
        <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm">
          <p className="text-sm font-medium text-slate-600 mb-1">Findings</p>
          <p className="text-2xl font-bold text-slate-900">{totalVulnerabilities}</p>
        </div>
        <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm">
          <p className="text-sm font-medium text-slate-600 mb-1">Duration</p>
          <p className="text-2xl font-bold text-slate-900">{durationLabel}</p>
        </div>
        <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm">
          <p className="text-sm font-medium text-slate-600 mb-1">Started</p>
          <p className="text-lg font-bold text-slate-900 whitespace-nowrap overflow-hidden text-ellipsis">{scan.startedAt ? formatSystemTime(scan.startedAt) : '-'}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="bg-white rounded-2xl shadow-sm p-6 border border-slate-200 lg:col-span-1">
          <h3 className="text-lg font-semibold text-slate-900 mb-4">Target Summary</h3>
          <div className="space-y-4 text-sm text-slate-700">
            <div className="flex items-center gap-3">
              <Shield className="w-4 h-4 text-emerald-600" />
              <span>Scan ID: <strong className="text-slate-900">{scan.id}</strong></span>
            </div>
            <div className="flex items-center gap-3">
              <Globe className="w-4 h-4 text-emerald-600" />
              <span>Target: <strong className="text-slate-900">{scan.target}</strong></span>
            </div>
            <div className="flex items-center gap-3">
              <Clock className="w-4 h-4 text-emerald-600" />
              <span>Started: <strong className="text-slate-900">{scan.startedAt ? formatSystemTime(scan.startedAt) : '-'}</strong></span>
            </div>
            <div className="flex items-center gap-3">
              <Clock className="w-4 h-4 text-emerald-600" />
              <span>Completed: <strong className="text-slate-900">{scan.completedAt ? formatSystemTime(scan.completedAt) : '-'}</strong></span>
            </div>
            
            <div className="pt-4 border-t border-slate-200 mt-4">
               <h4 className="text-sm font-semibold text-slate-900 mb-2">Findings Breakdown</h4>
               <div className="space-y-1 text-sm text-slate-600">
                 {displayedFindings.length > 0 ? (
                   <>
                     <div className="flex justify-between p-2 rounded bg-slate-50/50">
                       <span>Critical</span>
                       <span className="font-semibold text-red-500">
                         {displayedFindings.filter((f: any) => (f.severity || '').toLowerCase() === 'critical').length}
                       </span>
                     </div>
                     <div className="flex justify-between p-2 rounded bg-slate-50/50">
                       <span>High</span>
                       <span className="font-semibold text-orange-500">
                         {displayedFindings.filter((f: any) => (f.severity || '').toLowerCase() === 'high').length}
                       </span>
                     </div>
                     <div className="flex justify-between p-2 rounded bg-slate-50/50">
                       <span>Medium</span>
                       <span className="font-semibold text-yellow-500">
                         {displayedFindings.filter((f: any) => (f.severity || '').toLowerCase() === 'medium').length}
                       </span>
                     </div>
                     <div className="flex justify-between p-2 rounded bg-slate-50/50">
                       <span>Low</span>
                       <span className="font-semibold text-emerald-500">
                         {displayedFindings.filter((f: any) => (f.severity || '').toLowerCase() === 'low').length}
                       </span>
                     </div>
                   </>
                 ) : (
                   <>
                     <div className="flex justify-between p-2 rounded bg-slate-50/50"><span>Critical</span><span className="font-semibold text-red-500">{scan.findings.critical}</span></div>
                     <div className="flex justify-between p-2 rounded bg-slate-50/50"><span>High</span><span className="font-semibold text-orange-500">{scan.findings.high}</span></div>
                     <div className="flex justify-between p-2 rounded bg-slate-50/50"><span>Medium</span><span className="font-semibold text-yellow-500">{scan.findings.medium}</span></div>
                     <div className="flex justify-between p-2 rounded bg-slate-50/50"><span>Low</span><span className="font-semibold text-emerald-500">{scan.findings.low}</span></div>
                   </>
                 )}
               </div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-2xl shadow-sm p-6 border border-slate-200 lg:col-span-2 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-lg font-semibold text-slate-900">Full Report</h3>
            <button
              type="button"
              onClick={() => void downloadReport()}
              className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-emerald-400 text-slate-950 hover:bg-emerald-500 transition-colors"
            >
              Download JSON
            </button>
          </div>
          <div className="flex-1">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 stagger-fade">
              {reportOverview.map((item) => (
                <div key={item.label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm transition-all hover:-translate-y-0.5 hover:shadow-md">
                  <p className="text-xs uppercase tracking-wider text-slate-500 font-semibold">{item.label}</p>
                  <p className="text-lg font-semibold text-slate-900 mt-2">{item.value || '-'}</p>
                </div>
              ))}
            </div>
          </div>
          {detailedRisks.length ? (
            <div className="mt-4 border-t border-slate-200 pt-4 space-y-3">
              <h4 className="text-sm font-semibold text-slate-900">Vulnerability Report</h4>
              {detailedRisks.map((risk: any, idx: number) => {
                const evidenceId = `report-${idx}`;
                const rawEvidence = risk?.raw_output || risk?.raw_evidence || risk?.raw_code || '';
                const showEvidence = Boolean(evidenceOpen[evidenceId]);
                return (
                  <div key={`${risk?.title || 'risk'}-${idx}`} className="rounded-xl border border-slate-200 bg-white p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-slate-900">{risk?.title || 'Vulnerability'}</p>
                        <p className="text-xs text-slate-600 mt-1">{risk?.severity ? `Severity: ${risk.severity}` : 'Severity: unclassified'}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => toggleEvidence(evidenceId)}
                        className="text-xs px-3 py-1 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200 hover:bg-emerald-200"
                      >
                        Raw Evidence
                      </button>
                    </div>
                    {showEvidence ? (
                      <pre className="mt-3 text-xs font-mono text-slate-900 bg-slate-50 border border-slate-200 rounded-lg p-3 whitespace-pre-wrap overflow-x-auto">
                        {rawEvidence || 'Raw evidence unavailable.'}
                      </pre>
                    ) : null}
                    <div className="mt-3 text-xs text-emerald-700">
                      {risk?.mitigation || 'Mitigation guidance unavailable.'}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : null}
          <p className="text-xs text-slate-500 mt-3 text-right">Detailed report is available via the secure API download.</p>
        </div>
      </div>

      {scan.status === 'failed' ? (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-sm text-red-400 flex items-center gap-2 mb-6 shadow-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span className="font-medium">Scan execution failed. Check backend logs for internal analysis errors.</span>
        </div>
      ) : null}

      <div className="bg-white rounded-2xl shadow-sm p-6 border border-slate-200">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold text-slate-900">Findings & Mitigations</h3>
          <div className="text-sm font-medium text-slate-600 bg-slate-50 px-3 py-1 rounded-full border border-slate-200">
            {findingsLoading ? 'Loading...' : `${displayedFindings.length} Vulnerabilities`}
          </div>
        </div>

        {findingsError ? <div className="text-sm text-red-400 mb-3">{findingsError}</div> : null}
        {!findingsLoading && displayedFindings.length === 0 ? (
          <div className="text-sm text-slate-600 bg-slate-50/50 border border-slate-200 p-8 rounded-xl text-center">
            No vulnerabilities or findings were reported for this specific scan target.
          </div>
        ) : null}

        {displayedFindings.length ? (
          <div className="space-y-6">
            {displayedFindings.map((finding: any, idx: number) => {
              const findingId = finding?.id || finding?.title || `vuln-${idx}`;
              const findingTitle = finding?.title || finding?.name || 'Unknown Vulnerability';
              const findingDesc = finding?.description || finding?.details || finding?.info || 'No description provided.';
              const findingSev = finding?.severity || finding?.risk || 'low';
              const findingAsset = finding?.asset || finding?.hostname || finding?.target || 'Unknown Endpoint';
              
              const rawData = finding?.raw_output || finding?.raw_evidence || finding?.raw_code || finding?.raw_data || null;
              const techDetails = finding?.technical_details || finding?.explanation || finding?.details || findingDesc;
              const mitigationText = finding?.mitigation || finding?.fix || finding?.recommendation || 'Implement proper input validation and sanitization. Apply security patches and follow secure coding practices.';
              
              const evidenceId = `${findingId}-evidence`;
              const showEvidence = Boolean(evidenceOpen[evidenceId]);

              // Safety transform for raw data
              let formattedRawData = 'No raw evidence available.';
              if (rawData) {
                if (typeof rawData === 'object') {
                  formattedRawData = JSON.stringify(rawData, null, 2);
                } else {
                  formattedRawData = String(rawData);
                }
              }

              return (
                <div key={findingId} className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm hover:shadow-md transition-shadow">
                  <div className="p-6">
                    {/* Basic Info (Always visible) */}
                    <div className="flex items-start justify-between gap-4 mb-4">
                      <div className="flex items-center gap-3">
                        <h4 className="text-lg font-bold text-slate-900">{findingTitle}</h4>
                        <span className={`px-2.5 py-1 rounded-md text-xs font-bold uppercase shadow-sm ${severityBadge(findingSev)}`}>
                          {findingSev}
                        </span>
                      </div>
                    </div>
                    
                    <div className="space-y-5">
                      <div>
                        <p className="text-sm text-slate-700 leading-relaxed">{findingDesc}</p>
                      </div>
                      
                      <div>
                        <p className="text-sm">
                          <span className="font-semibold text-slate-700">Affected Endpoint: </span>
                          <span className="font-mono text-slate-600 bg-slate-100 px-2 py-0.5 rounded text-xs">{findingAsset}</span>
                        </p>
                      </div>

                      {/* Dropdown (Raw Data ONLY) */}
                      <div className="border border-slate-200 rounded-lg overflow-hidden bg-slate-50/50 mt-4">
                        <button
                          type="button"
                          onClick={() => toggleEvidence(evidenceId)}
                          className="w-full flex items-center justify-between px-4 py-3 bg-slate-50 hover:bg-slate-100 transition-colors cursor-pointer text-left focus:outline-none"
                        >
                          <span className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                            <span className="text-slate-400 text-[10px] w-4 text-center">{showEvidence ? '▼' : '▶'}</span> View Raw Data
                          </span>
                        </button>
                        {showEvidence && (
                          <div className="p-4 border-t border-slate-200 bg-white">
                            <pre className="text-xs font-mono text-slate-800 bg-slate-900 text-slate-200 p-4 rounded-lg overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto custom-scrollbar">
                              {formattedRawData}
                            </pre>
                          </div>
                        )}
                      </div>

                      {/* Technical Details (Outside dropdown) */}
                      <div className="bg-blue-50/50 p-4 rounded-lg border border-blue-100">
                        <h5 className="text-sm font-bold text-blue-900 mb-2">Technical Details:</h5>
                        <p className="text-sm text-blue-800 leading-relaxed whitespace-pre-wrap">
                          {techDetails}
                        </p>
                      </div>

                      {/* Mitigation / Prevention (Outside dropdown) */}
                      <div className="bg-emerald-50/50 p-4 rounded-lg border border-emerald-100">
                        <h5 className="text-sm font-bold text-emerald-900 mb-2">Mitigation:</h5>
                        <p className="text-sm text-emerald-800 leading-relaxed whitespace-pre-wrap">
                          {mitigationText}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : null}
      </div>
    </div>
  );
}
