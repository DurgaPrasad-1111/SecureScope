import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../api/client'
import Layout from '../components/Layout'
import ConfirmDialog from '../components/ConfirmDialog'
import { useAuth } from '../context/AuthContext'

function formatDate(value) {
  if (!value) return '-'
  return new Date(value).toLocaleString()
}

export default function ReportsPage() {
  const { user } = useAuth()
  const [reports, setReports] = useState([])
  const [status, setStatus] = useState('')
  const [clearing, setClearing] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)

  const canClear = user?.role !== 'Viewer'

  const loadData = async () => {
    try {
      const { data } = await api.get('/reports/')
      setReports(data)
    } catch {
      setReports([])
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const downloadReport = async (reportId, scanId) => {
    setStatus('Downloading report...')
    try {
      const res = await api.get(`/reports/${reportId}/download`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `securescope_report_${scanId}.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
      setStatus('Download complete')
    } catch {
      setStatus('Download failed')
    }
  }

  const clearScans = async () => {
    if (!canClear || clearing) return

    setClearing(true)
    setStatus('Clearing previous scans...')
    try {
      const { data } = await api.delete('/scans/')
      setStatus(`${data.detail} (${data.scope})`)
      await loadData()
    } catch (err) {
      setStatus(err?.response?.data?.detail || 'Failed to clear scan history')
    } finally {
      setClearing(false)
      setConfirmOpen(false)
    }
  }

  return (
    <Layout>
      <div className="card">
        <div className="page-head">
          <h2>Scan Intelligence</h2>
          <button className="danger-btn" onClick={() => setConfirmOpen(true)} disabled={!canClear || clearing}>
            {clearing ? 'Clearing...' : 'Clear Previous Scans'}
          </button>
        </div>

        {!canClear && <p className="muted-note">Viewer role is read-only. Ask Developer/Security Analyst/Admin to clear scan history.</p>}

        <table>
          <thead>
            <tr>
              <th>Report ID</th>
              <th>Domain</th>
              <th>Scan ID</th>
              <th>Scanned At</th>
              <th>Risk</th>
              <th>Report Generated</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td>{r.user_report_id ?? r.id}</td>
                <td>{r.domain || '-'}</td>
                <td>{r.scan_id}</td>
                <td>{formatDate(r.scanned_at)}</td>
                <td>{r.risk_score}</td>
                <td>{formatDate(r.created_at)}</td>
                <td>
                  <Link to={`/scan/${r.scan_id}`} className="table-action-link">View</Link>
                  {' '}
                  <button onClick={() => downloadReport(r.id, r.scan_id)}>Download PDF</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <p className="status-msg">{status}</p>
      </div>
      <ConfirmDialog
        open={confirmOpen}
        title="Clear Previous Scans"
        message="This will clear previous scans in your allowed scope, including findings and reports. Do you want to continue?"
        confirmLabel="Yes, Clear"
        cancelLabel="No, Keep Data"
        onConfirm={clearScans}
        onCancel={() => setConfirmOpen(false)}
        loading={clearing}
      />
    </Layout>
  )
}

