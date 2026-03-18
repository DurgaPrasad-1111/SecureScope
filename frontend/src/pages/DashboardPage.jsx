import { useEffect, useMemo, useState } from 'react'
import api from '../api/client'
import Layout from '../components/Layout'
import RiskGauge from '../components/RiskGauge'
import { useAuth } from '../context/AuthContext'

const scanModules = [
  { key: 'port_scan', label: 'Port Scan' },
  { key: 'subdomain_enum', label: 'Subdomain Enumeration' },
  { key: 'dns_records', label: 'DNS Records Inspection' },
  { key: 'tls_check', label: 'SSL/TLS Configuration Check' },
  { key: 'header_validation', label: 'HTTP Security Headers Validation' },
  { key: 'tech_fingerprint', label: 'Technology Fingerprinting' },
  { key: 'osint_metadata', label: 'OSINT Metadata Collection' },
  { key: 'cookie_flags', label: 'Cookie Flags Check' },
  { key: 'directory_enum', label: 'Directory Enumeration' },
  { key: 'admin_panel_probe', label: 'Admin Panel Exposure Probe' },
  { key: 'rate_limit_probe', label: 'Rate-Limit Behavior Probe' },
  { key: 'xss_probe', label: 'Reflected XSS Probe (Heuristic)' },
  { key: 'sqli_probe', label: 'SQLi Error Probe (Heuristic)' },
  { key: 'csrf_probe', label: 'CSRF Token Hint Probe (Heuristic)' },
]

function normalizeDomain(raw) {
  const input = raw.trim().toLowerCase()
  const noProto = input.replace(/^https?:\/\//, '')
  return noProto.split('/')[0]
}

function severityWeight(level) {
  if (level === 'Critical') return 4
  if (level === 'High') return 3
  if (level === 'Medium') return 2
  return 1
}

function prettyEvidence(value) {
  if (!value) return 'N/A'
  try {
    const obj = JSON.parse(value)
    return JSON.stringify(obj, null, 2)
  } catch {
    return String(value)
  }
}

export default function DashboardPage() {
  const { user } = useAuth()
  const [profile, setProfile] = useState(null)
  const [stats, setStats] = useState({ scans_performed: 0 })
  const [domain, setDomain] = useState('')
  const [status, setStatus] = useState('')
  const [loading, setLoading] = useState(false)
  const [reportData, setReportData] = useState(null)
  const [selectedModules, setSelectedModules] = useState([])
  const [progress, setProgress] = useState([])
  const [durationMs, setDurationMs] = useState(0)

  const canRunScan = user?.role === 'Security Analyst' || user?.role === 'Admin'

  useEffect(() => {
    api.get('/users/me/details').then(({ data }) => setProfile(data)).catch(() => setProfile(null))
    api.get('/users/me/stats').then(({ data }) => setStats(data)).catch(() => setStats({ scans_performed: 0 }))
  }, [])

  const toggleModule = (key) => {
    setSelectedModules((prev) => (prev.includes(key) ? prev.filter((m) => m !== key) : [...prev, key]))
  }

  const selectAllModules = () => setSelectedModules(scanModules.map((m) => m.key))

  const submitScan = async (e) => {
    e.preventDefault()
    if (!canRunScan) {
      setStatus('You do not have permission to run scans.')
      return
    }

    if (selectedModules.length === 0) {
      setStatus('Select at least one scan module.')
      return
    }

    setLoading(true)
    setStatus('Running deep reconnaissance pipeline...')
    setReportData(null)

    const start = performance.now()
    const selected = scanModules.filter((m) => selectedModules.includes(m.key))
    setProgress(selected.map((m, i) => ({ ...m, state: i === 0 ? 'running' : 'pending' })))

    let i = 0
    const ticker = setInterval(() => {
      i += 1
      setProgress((prev) => prev.map((p, idx) => {
        if (idx < i) return { ...p, state: 'done' }
        if (idx === i) return { ...p, state: 'running' }
        return p
      }))
    }, 850)

    try {
      const target = normalizeDomain(domain)
      const { data: scan } = await api.post('/scans/', { domain: target, modules: selectedModules })
      const { data: details } = await api.get(`/scans/${scan.id}`)
      const { data: reports } = await api.get('/reports/')
      const report = reports.find((r) => r.scan_id === scan.id) || null

      setReportData({ scan: details.scan, findings: details.findings, module_results: details.module_results || {}, report })
      const duration = details.duration_ms ? `${(details.duration_ms / 1000).toFixed(2)}s` : `${((performance.now() - start) / 1000).toFixed(2)}s`
      setStatus(`Scan complete. Risk score: ${details.scan.risk_score}/100. Total runtime: ${duration}`)
    } catch (err) {
      const code = err?.response?.status
      if (err?.code === 'ECONNABORTED') {
        setStatus('Scan is taking longer than expected. Please retry, or reduce module count if target is slow.')
      } else if (code === 504) {
        setStatus('Scan is still running on server and gateway timed out. Open Scan Intelligence to view results once completed.')
      } else if (code === 403) {
        setStatus('Scan blocked by policy. Ensure CSRF token is present and your role is Security Analyst/Admin.')
      } else if (code === 422) {
        setStatus('Invalid domain input. Enter only domain name, for example: scanme.nmap.org')
      } else if (code === 401) {
        setStatus('Session expired or unauthorized. Please login again.')
      } else {
        setStatus(err?.response?.data?.detail || 'Scan failed due to unexpected error.')
      }
    } finally {
      clearInterval(ticker)
      setProgress((prev) => prev.map((p) => ({ ...p, state: 'done' })))
      setLoading(false)
      setDurationMs(Math.round(performance.now() - start))
    }
  }

  const downloadReport = async () => {
    if (!reportData?.report) return
    try {
      const res = await api.get(`/reports/${reportData.report.id}/download`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `securescope_report_${reportData.scan.id}.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
    } catch {
      setStatus('Report download failed')
    }
  }

  const orderedFindings = useMemo(() => {
    if (!reportData?.findings) return []
    return [...reportData.findings].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
  }, [reportData])

  const moduleLabelMap = useMemo(
    () => Object.fromEntries(scanModules.map((m) => [m.key, m.label])),
    [],
  )

  return (
    <Layout>
      {profile && (
        <section className="card">
          <h2>User Profile</h2>
          <div className="profile-grid">
            <p><strong>Name:</strong> {profile.full_name}</p>
            <p><strong>Email:</strong> {profile.email}</p>
            <p><strong>Role:</strong> {profile.role}</p>
            <p><strong>Organization:</strong> {profile.organization}</p>
            <p><strong>Job Title:</strong> {profile.job_title}</p>
            <p><strong>Phone:</strong> {profile.phone}</p>
            <p><strong>Total Scans Performed:</strong> {stats.scans_performed}</p>
            <p className="profile-purpose"><strong>Purpose:</strong> {profile.purpose}</p>
          </div>
        </section>
      )}

      <section className="hero-card">
        <h2>Secure Scan</h2>
        <p>SaaS-style deep scan flow with module-level telemetry and raw evidence collection.</p>

        <form onSubmit={submitScan} className="scan-form">
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com or https://example.com"
            required
            disabled={!canRunScan || loading}
          />
          <button type="submit" disabled={!canRunScan || loading} className="primary-btn">
            {loading ? 'Scanning...' : 'Start Deep Scan'}
          </button>
        </form>

        <div className="module-head">
          <h4>Scan Modules</h4>
          <button type="button" className="primary-btn" onClick={selectAllModules} disabled={loading}>Select All</button>
        </div>
        <div className="module-grid">
          {scanModules.map((m) => (
            <label key={m.key} className="module-item">
              <input
                type="checkbox"
                checked={selectedModules.includes(m.key)}
                onChange={() => toggleModule(m.key)}
                disabled={loading}
              />
              <span>{m.label}</span>
            </label>
          ))}
        </div>

        {progress.length > 0 && (
          <div className="progress-list">
            {progress.map((p) => (
              <div key={p.key} className="progress-row">
                <span className={`progress-icon progress-${p.state}`}>{p.state === 'done' ? '\u2713' : ''}</span>
                <span>{p.label}</span>
              </div>
            ))}
          </div>
        )}

        {durationMs > 0 && <p className="muted-note">Last scan completed in {(durationMs / 1000).toFixed(2)} seconds.</p>}

        {!canRunScan && <p className="muted-note">Only Security Analyst and Admin can run scans.</p>}
        <p className="status-msg">{status}</p>
      </section>

      {reportData && (
        <section className="report-card">
          <div className="report-grid">
            <div>
              <h3>Vulnerability Report - {reportData.scan.domain}</h3>
              <p className="muted-note">Scanned on {new Date(reportData.scan.created_at).toLocaleString()}</p>
              {reportData.module_results?.subdomain_enum?.raw?.subdomains?.length > 0 && (
                <div className="subdomain-pill-list">
                  {reportData.module_results.subdomain_enum.raw.subdomains.map((sub) => (
                    <span key={sub} className="subdomain-pill">{sub}</span>
                  ))}
                </div>
              )}
              <div className="finding-list">
                {orderedFindings.length === 0 && <p>No findings detected in current scan scope.</p>}
                {orderedFindings.map((f) => (
                  <article key={f.id} className="finding-item">
                    <div className="finding-title-row">
                      <h4>{f.title}</h4>
                      <span className={`sev-tag sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
                    </div>
                    <p>{f.description}</p>
                    <p><strong>STRIDE:</strong> {f.stride}</p>
                    <p><strong>Remediation:</strong> {f.remediation}</p>
                    <details>
                      <summary><strong>Raw Evidence</strong></summary>
                      <pre className="evidence-block">{prettyEvidence(f.evidence)}</pre>
                    </details>
                  </article>
                ))}
              </div>
            </div>

            <div className="risk-panel">
              <RiskGauge score={reportData.scan.risk_score} />
              <p className="risk-caption">Detailed telemetry-backed risk intelligence with module evidence traces.</p>
              <h4>Module Telemetry</h4>
              <div className="telemetry-list">
                {Object.entries(reportData.module_results || {}).map(([k, v]) => (
                  <div key={k} className="telemetry-item">
                    <strong>{moduleLabelMap[k] || k}</strong>
                    <span>{v.duration_ms} ms</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="card recon-data-card">
            <h4>Recon Raw Data</h4>
            <p className="muted-note">Complete module output captured from this scan.</p>
            {Object.entries(reportData.module_results || {}).map(([k, v]) => (
              <details key={`raw-${k}`} className="raw-module-block">
                <summary>{moduleLabelMap[k] || k}</summary>
                <pre className="evidence-block">{JSON.stringify(v.raw ?? {}, null, 2)}</pre>
              </details>
            ))}
          </div>

          <div className="report-footer">
            <button className="primary-btn" onClick={downloadReport} disabled={!reportData.report}>Download Detailed PDF Report</button>
          </div>
        </section>
      )}
    </Layout>
  )
}
