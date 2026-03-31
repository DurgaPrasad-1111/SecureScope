import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { AlertTriangle, Play, Settings, Target, ShieldAlert } from 'lucide-react';

import { getRecentScans } from '../../../api/dashboard';
import { createScan, validateTargets } from '../../../api/scans';
import { handleApiError } from '../../../utils/errorHandler';
import { useAuth } from '../../context/AuthContext';
import { toast } from 'sonner';

type ScanTypeUi = 'normal' | 'quick';

function parseTargets(raw: string) {
  return raw
    .split(/[\n,]+/g)
    .map((t) => t.trim())
    .filter(Boolean);
}

export default function NewScan() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user } = useAuth();
  const [targetsText, setTargetsText] = useState(searchParams.get('target') ?? '');
  const [scanType, setScanType] = useState<ScanTypeUi>('normal');
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [validationSummary, setValidationSummary] = useState<{ valid: number; invalid: number } | null>(null);

  const isAdmin = user?.role === 'admin';

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const data = await getRecentScans({ limit: 5, offset: 0 });
        if (mounted) setRecentScans(data.scans);
      } catch {
        if (mounted) setRecentScans([]);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (isAdmin) setScanType('quick');
  }, [isAdmin]);

  const scanTypes = useMemo(
    () => [
      { id: 'normal' as const, name: 'Passive Scan', icon: Target, description: 'Passive reconnaissance only (safe analysis, allows for all users)', duration: '~10-60 sec' },
      { id: 'quick' as const, name: 'Active Scan', icon: Settings, description: 'Performs deeper testing with payloads and fuzzing (Admins only)', duration: '~30-60 sec' },
    ],
    [],
  );

  const scanTools = useMemo(
    () => ({
      normal: [
        'WHOIS Lookup - Domain registration details',
        'DNS Enumeration - Records (A, MX, TXT, NS)',
        'Subdomain Discovery (OSINT)',
        'SSL/TLS Certificate Analysis',
        'HTTP Header Analysis',
        'Technology Fingerprinting (server, framework, CMS)',
        'Public Data Collection (OSINT) - GitHub leaks, metadata, etc.',
        'Search Engine Reconnaissance (Google Dorking)',
      ],
      quick: [
        'Port Scanning - Open ports & services',
        'Service Enumeration',
        'Vulnerability Scanning (known CVEs)',
        'SQL Injection Testing',
        'Cross-Site Scripting (XSS) Testing',
        'Directory & File Brute Forcing',
        'Authentication Testing (login flaws)',
        'Session Management Testing',
        'API Endpoint Testing',
      ],
    }),
    [],
  );

  const passiveOptionsDefs = useMemo(() => [
    { key: 'dnsEnumeration', label: 'DNS Enumeration', description: 'Collect DNS records (A, MX, TXT, NS, CNAME)' },
    { key: 'subdomainDiscovery', label: 'Subdomain Discovery', description: 'Find subdomains via OSINT techniques' },
    { key: 'sslAnalysis', label: 'SSL/TLS Analysis', description: 'Check certificate validity and configuration' },
    { key: 'technologyDetection', label: 'Technology Detection', description: 'Identify server, framework, and CMS' },
    { key: 'portScanning', label: 'Port Scanning (Passive)', description: 'Non-intrusive port detection' },
  ], []);

  const activeOptionsDefs = useMemo(() => [
    { key: 'portScanning', label: 'Port Scanning', description: 'Full port scan with service detection' },
    { key: 'vulnerabilityAssessment', label: 'Vulnerability Assessment', description: 'Scan for known CVEs and weaknesses' },
    { key: 'sqlInjectionTesting', label: 'SQL Injection Testing', description: 'Test for SQL injection vulnerabilities' },
    { key: 'xssTesting', label: 'XSS Testing', description: 'Test for cross-site scripting vulnerabilities' },
    { key: 'directoryBruteforce', label: 'Directory Bruteforce', description: 'Discover hidden directories and files' },
    { key: 'authenticationTesting', label: 'Authentication Testing', description: 'Test login mechanisms and sessions' },
    { key: 'apiEndpointTesting', label: 'API Endpoint Testing', description: 'Discover and test API endpoints' },
    { key: 'sslAnalysis', label: 'SSL/TLS Analysis', description: 'Check certificate validity and configuration' },
    { key: 'technologyDetection', label: 'Technology Detection', description: 'Identify server, framework, and CMS' },
  ], []);

  const currentOptionsDefs = scanType === 'normal' ? passiveOptionsDefs : activeOptionsDefs;

  const [options, setOptions] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    currentOptionsDefs.forEach(opt => { initial[opt.key] = true; });
    return initial;
  });

  useEffect(() => {
    const updated: Record<string, boolean> = {};
    currentOptionsDefs.forEach(opt => { updated[opt.key] = true; });
    setOptions(updated);
  }, [currentOptionsDefs]);

  const allOptionsEnabled = currentOptionsDefs.every(opt => options[opt.key]);
  const anyOptionsEnabled = currentOptionsDefs.some(opt => options[opt.key]);

  const notifications = useMemo(
    () => ({
      emailOnCompletion: true,
      notifyOnCriticalFindings: true,
      slackWebhook: '',
      customWebhook: '',
    }),
    [],
  );

  const handleOptionChange = (key: string) => setOptions((prev) => ({ ...prev, [key]: !prev[key] }));
  const setAllOptions = (value: boolean) => {
    const updated: Record<string, boolean> = {};
    currentOptionsDefs.forEach(opt => { updated[opt.key] = value; });
    setOptions(updated);
  };
  const scanTypeMap = useMemo(() => ({ normal: 'passive', quick: 'active' } as const), []);

  const onValidate = async () => {
    const targets = parseTargets(targetsText);
    if (!targets.length) {
      setValidationSummary(null);
      return;
    }

    try {
      const result = await validateTargets(targets);
      setValidationSummary({ valid: result.summary.validTargets, invalid: result.summary.invalidTargets });
    } catch (error) {
      handleApiError(error);
      setValidationSummary(null);
    }
  };

  const onStart = async () => {
    const targets = parseTargets(targetsText);
    if (!targets.length) {
      toast.error('At least one target is required');
      return;
    }

    setSubmitting(true);
    try {
      const response = await createScan({
        targets,
        scanType: scanTypeMap[scanType] === 'passive' ? 'normal_scan' : (scanTypeMap[scanType] === 'active' ? 'quick_scan' : 'full_scan'),
        options,
        schedule: { type: 'immediate', scheduledAt: null },
        notifications: {
          emailOnCompletion: notifications.emailOnCompletion,
          notifyOnCriticalFindings: notifications.notifyOnCriticalFindings,
          slackWebhook: notifications.slackWebhook.trim() || null,
          customWebhook: notifications.customWebhook.trim() || null,
        },
        priority: 'normal',
        name: null,
        description: null,
        tags: [],
      });

      navigate(`/scan/${response.scanId}`);
    } catch (error) {
      handleApiError(error);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-slate-900">Configure New Scan</h1>
        <p className="text-slate-600 mt-1">Create a scan job via the backend scan API</p>
      </div>

      <div className="max-w-4xl mx-auto space-y-6">
        <div className="glass-surface rounded-2xl p-6">
          <h3 className="text-xl font-semibold text-slate-900 mb-6">Scan Configuration</h3>

          <div className="mb-6">
            <label className="block text-sm font-medium text-slate-900 mb-2">Scan Targets</label>
            <textarea
              rows={4}
              value={targetsText}
              onChange={(event) => setTargetsText(event.target.value)}
              onBlur={() => void onValidate()}
              placeholder="Enter one target per line\nExample:\nacme-corp.com\n203.0.113.0/24\n*.acme-corp.com"
              className="w-full px-4 py-3 border border-slate-200 rounded-xl bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:border-transparent resize-none"
            />
            {validationSummary ? (
              <p className="text-sm text-slate-600 mt-2">
                Validation: {validationSummary.valid} valid, {validationSummary.invalid} invalid
              </p>
            ) : (
              <p className="text-sm text-slate-600 mt-2">Targets are validated automatically when you leave the field.</p>
            )}
          </div>

          <div className="mb-8">
            <label className="block text-sm font-medium text-slate-900 mb-4">Scan Type</label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {scanTypes.map((type) => {
                const Icon = type.icon;
                const disabled = type.id === 'quick' && !isAdmin;
                return (
                  <button
                    key={type.id}
                    type="button"
                    onClick={() => setScanType(type.id)}
                    disabled={disabled}
                    className={`
                      p-4 rounded-xl border-2 text-left transition-all
                      ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
                      ${scanType === type.id ? 'border-emerald-400 bg-emerald-100 shadow-lg shadow-emerald-200/30' : 'border-slate-200 bg-white hover:border-emerald-300'}
                    `}
                  >
                    <div className="flex items-center gap-3 mb-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${scanType === type.id ? 'bg-emerald-200 text-emerald-800' : 'bg-slate-100 text-slate-500'}`}>
                        <Icon className="w-5 h-5" />
                      </div>
                      <div>
                        <h4 className="font-semibold text-slate-900">{type.name}</h4>
                      </div>
                    </div>
                    <p className="text-sm text-slate-600 mb-2">{type.description}</p>
                    <p className="text-xs text-slate-500">{type.duration}</p>
                  </button>
                );
              })}
            </div>
            {!isAdmin ? (
              <p className="text-xs text-slate-600 mt-2">Active Scan requires admin privileges. You may run Passive Scans.</p>
            ) : null}

            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 p-4">
              <p className="text-xs uppercase tracking-wide text-emerald-700 font-semibold mb-2">Tools in this scan</p>
              <div className="flex flex-wrap gap-2">
                {scanTools[scanType].map((tool) => (
                  <span key={tool} className="text-xs px-3 py-1 rounded-full bg-white border border-emerald-200 text-emerald-800">
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div>
            <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
              <label className="block text-sm font-medium text-slate-900">Scan Options</label>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setAllOptions(true)}
                  disabled={allOptionsEnabled}
                  className="text-xs px-3 py-1 rounded-full border border-emerald-300 text-emerald-800 hover:bg-emerald-100 disabled:opacity-50"
                >
                  Select all
                </button>
                <button
                  type="button"
                  onClick={() => setAllOptions(false)}
                  disabled={!anyOptionsEnabled}
                  className="text-xs px-3 py-1 rounded-full border border-slate-200 text-slate-600 hover:bg-slate-100 disabled:opacity-50"
                >
                  Clear all
                </button>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {currentOptionsDefs.map((opt) => (
                <label key={opt.key} className="flex items-center gap-3 p-3 rounded-lg hover:bg-slate-100 cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={options[opt.key] ?? false} 
                    onChange={() => handleOptionChange(opt.key)} 
                    className="w-5 h-5 text-emerald-500 border-slate-300 rounded focus:ring-emerald-400" 
                  />
                  <div className="flex flex-col">
                    <span className="text-slate-700 font-medium">{opt.label}</span>
                    <span className="text-xs text-slate-500">{opt.description}</span>
                  </div>
                </label>
              ))}
            </div>
            
            {scanType === 'quick' && (
              <div className="mt-4 p-4 rounded-xl border border-amber-200 bg-amber-50">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-600" />
                  <p className="text-sm font-semibold text-amber-800">Active scan may affect target system</p>
                </div>
                <p className="text-xs text-amber-700 mt-1">
                  This scan performs aggressive testing including vulnerability assessment, SQL injection testing, and directory brute forcing. 
                  Only use on systems you have permission to test.
                </p>
              </div>
            )}
          </div>
        </div>

        <div className="glass-surface rounded-2xl p-6">
          <h3 className="text-xl font-semibold text-slate-900 mb-6">Start Scan</h3>
          <div className="flex items-center justify-between">
            <button type="button" onClick={() => void onStart()} disabled={submitting} className="flex items-center gap-2 px-6 py-3 rounded-xl bg-emerald-400 text-slate-950 font-semibold hover:bg-emerald-500 disabled:opacity-60">
              <Play className="w-5 h-5" />
              {submitting ? 'Starting...' : 'Start Scan'}
            </button>
            <button type="button" onClick={() => void onValidate()} className="text-sm text-emerald-700 hover:text-emerald-900">
              Validate targets
            </button>
          </div>
        </div>

        <div className="glass-surface rounded-2xl p-6">
          <h3 className="text-xl font-semibold text-slate-900 mb-4">Recent Scans</h3>
          <div className="space-y-2">
            {recentScans.map((scan) => (
              <button key={scan.id} type="button" onClick={() => navigate(`/scan/${scan.id}`)} className="w-full flex items-center justify-between p-3 rounded-xl hover:bg-slate-100">
                <div className="text-left">
                  <p className="text-sm font-medium text-slate-900">{scan.target}</p>
                  <p className="text-xs text-slate-600">{scan.typeLabel} - {scan.status}</p>
                </div>
                <span className="text-xs text-slate-500">{scan.relativeTime}</span>
              </button>
            ))}
            {!recentScans.length ? <p className="text-sm text-slate-600">No recent scans.</p> : null}
          </div>
        </div>
      </div>
    </div>
  );
}

