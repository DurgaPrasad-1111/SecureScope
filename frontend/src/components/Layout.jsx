import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Layout({ children }) {
  const { user, logout } = useAuth()

  return (
    <div className="container">
      <nav className="nav">
        <div className="brand-block">
          <h1>SecureScope</h1>
          <p>Web Reconnaissance & Risk Intelligence</p>
        </div>
        <div className="links">
          <Link className="nav-link" to="/about">About</Link>
          <Link className="nav-link" to="/">Dashboard</Link>
          <Link className="nav-link" to="/intelligence">Scan Intelligence</Link>
          <span className="role-chip">{user?.role}</span>
          <button className="logout-btn" onClick={logout}>Logout</button>
        </div>
      </nav>
      <main>{children}</main>
    </div>
  )
}
