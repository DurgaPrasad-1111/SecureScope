import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const roleOrder = {
  Viewer: 1,
  Developer: 2,
  'Security Analyst': 3,
  Admin: 4,
}

export default function ProtectedRoute({ children, minRole = 'Viewer' }) {
  const { user } = useAuth()
  if (!user) return <Navigate to="/login" replace />
  if ((roleOrder[user.role] || 0) < (roleOrder[minRole] || 99)) return <Navigate to="/" replace />
  return children
}
