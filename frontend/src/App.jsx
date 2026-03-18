import { Navigate, Route, Routes } from 'react-router-dom'
import AuthPage from './pages/AuthPage'
import AboutPage from './pages/AboutPage'
import DashboardPage from './pages/DashboardPage'
import HistoryPage from './pages/HistoryPage'
import ScanDetailPage from './pages/ScanDetailPage'
import ReportsPage from './pages/ReportsPage'
import ProtectedRoute from './routes/ProtectedRoute'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<AuthPage />} />
      <Route path="/about" element={<ProtectedRoute minRole="Viewer"><AboutPage /></ProtectedRoute>} />
      <Route path="/" element={<ProtectedRoute minRole="Viewer"><DashboardPage /></ProtectedRoute>} />
      <Route path="/history" element={<ProtectedRoute minRole="Developer"><HistoryPage /></ProtectedRoute>} />
      <Route path="/intelligence" element={<ProtectedRoute minRole="Viewer"><ReportsPage /></ProtectedRoute>} />
      <Route path="/reports" element={<Navigate to="/intelligence" replace />} />
      <Route path="/scan/:id" element={<ProtectedRoute minRole="Developer"><ScanDetailPage /></ProtectedRoute>} />
      <Route path="*" element={<Navigate to="/about" replace />} />
    </Routes>
  )
}
