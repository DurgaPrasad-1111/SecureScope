import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import api from '../api/client'
import Layout from '../components/Layout'
import RiskGauge from '../components/RiskGauge'

const moduleLabelMap = {
  port_scan: 'Port Scan',
  subdomain_enum: 'Subdomain Enumeration',
  dns_records: 'DNS Records Inspection',
  tls_check: 'SSL/TLS Configuration Check',
  header_validation: 'HTTP Security Headers Validation',
  tech_fingerprint: 'Technology Fingerprinting',
  osint_metadata: 'OSINT Metadata Collection',
  cookie_flags: 'Cookie Flags Check',
  directory_enum: 'Directory Enumeration',
  admin_panel_probe: 'Admin Panel Exposure Probe',
  rate_limit_probe: 'Rate-Limit Behavior Probe',
  xss_probe: 'Reflected XSS Probe (Heuristic)',
  sqli_probe: 'SQLi Error Probe (Heuristic)',
  csrf_probe: 'CSRF Token Hint Probe (Heuristic)',
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

export default function ScanDetailPage() {
  const { id } = useParams()
  const [data, setData] = useState(null)
  const [status, setStatus] = useState('')
  const [report, setReport] = useState(null)

  useEffect(() => {
    const load = async () => {
      try {
        const [{ data: details }, { data: reports }] = await Promise.all([
          api.get(`/scans/${id}`),
          api.get('/reports/'),
        ])
        setData(details)
        setReport(reports.find((r) => r.scan_id === Number(id)) || null)
      } catch {
        setData(null)
      }
    }
    load()
  }, [id])

  const orderedFindings = data?.findings
    ? [...data.findings].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
    : []

  const downloadReport = async () => {
    if (!report) return
    setStatus('Downloading report...')
    try {
      const res = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `securescope_report_${report.scan_id}.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
      setStatus('Download complete')
    } catch {
      setStatus('Download failed')
    }
  }

  return (
    <Layout>
      <section className="report-card">
        <h3>Scan #{id} Detailed Report</h3>
        {!data && <p>No data</p>}
        {data && (
          <>
            <div className="report-grid">
              <div>
                <h3>Vulnerability Report - {data.scan.domain}</h3>
                <p className="muted-note">Scanned on {new Date(data.scan.created_at).toLocaleString()}</p>
                {data.module_results?.subdomain_enum?.raw?.subdomains?.length > 0 && (
                  <div className="subdomain-pill-list">
                    {data.module_results.subdomain_enum.raw.subdomains.map((sub) => (
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
                <RiskGauge score={data.scan.risk_score} />
                <p className="risk-caption">Detailed telemetry-backed risk intelligence with module evidence traces.</p>
                <h4>Module Telemetry</h4>
                <div className="telemetry-list">
                  {Object.entries(data.module_results || {}).map(([k, v]) => (
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
              {Object.entries(data.module_results || {}).map(([k, v]) => (
                <details key={`raw-${k}`} className="raw-module-block">
                  <summary>{moduleLabelMap[k] || k}</summary>
                  <pre className="evidence-block">{JSON.stringify(v.raw ?? {}, null, 2)}</pre>
                </details>
              ))}
            </div>

            <div className="report-footer">
              <button className="primary-btn" onClick={downloadReport} disabled={!report}>Download Detailed PDF Report</button>
            </div>
            {status && <p className="status-msg">{status}</p>}
          </>
        )}
      </section>
    </Layout>
  )
}
