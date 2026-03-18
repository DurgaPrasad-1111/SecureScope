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

export default function HistoryPage() {
  const { user } = useAuth()
  const [scans, setScans] = useState([])
  const [status, setStatus] = useState('')
  const [clearing, setClearing] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)

  const canClear = user?.role !== 'Viewer'

  const loadData = async () => {
    try {
      const { data } = await api.get('/scans/')
      setScans(data)
    } catch {
      setScans([])
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const clearScans = async () => {
    if (!canClear || clearing) return

    setClearing(true)
    setStatus('Clearing scan history...')
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
          <h2>Scan History</h2>
          <button className="danger-btn" onClick={() => setConfirmOpen(true)} disabled={!canClear || clearing}>
            {clearing ? 'Clearing...' : 'Clear Previous Scans'}
          </button>
        </div>

        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Domain</th>
              <th>Status</th>
              <th>Risk</th>
              <th>Scanned At</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td>{s.id}</td>
                <td>{s.domain}</td>
                <td>{s.status}</td>
                <td>{s.risk_score}</td>
                <td>{formatDate(s.created_at)}</td>
                <td><Link to={`/scan/${s.id}`}>View Report</Link></td>
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

