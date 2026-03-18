import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const roles = ['Security Analyst', 'Developer', 'Viewer']

export default function AuthPage() {
  const navigate = useNavigate()
  const { login, register } = useAuth()

  const [mode, setMode] = useState('login')
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')

  const [loginForm, setLoginForm] = useState({ email: '', password: '' })
  const [registerForm, setRegisterForm] = useState({
    email: '',
    full_name: '',
    password: '',
    role: 'Security Analyst',
    organization: '',
    purpose: '',
    job_title: '',
    phone: '',
  })

  const submitLogin = async (e) => {
    e.preventDefault()
    setError('')
    setStatus('Signing in...')
    try {
      await login(loginForm.email.trim(), loginForm.password)
      setStatus('')
      navigate('/about')
    } catch (err) {
      setStatus('')
      setError(err?.response?.data?.detail || 'Login failed. Verify credentials and try again.')
    }
  }

  const submitRegister = async (e) => {
    e.preventDefault()
    setError('')
    setStatus('Creating account...')
    try {
      await register({
        email: registerForm.email.trim(),
        full_name: registerForm.full_name.trim(),
        password: registerForm.password,
        role: registerForm.role,
        organization: registerForm.organization.trim(),
        purpose: registerForm.purpose.trim(),
        job_title: registerForm.job_title.trim(),
        phone: registerForm.phone.trim(),
      })
      setStatus('Registration successful. You can sign in now.')
      setMode('login')
    } catch (err) {
      setStatus('')
      setError(err?.response?.data?.detail || 'Registration failed.')
    }
  }

  return (
    <div className="auth-shell">
      <section className="auth-panel">
        <div className="auth-head">
          <h1>SecureScope</h1>
          <p>Enterprise-grade web reconnaissance and risk intelligence</p>
        </div>

        <div className="auth-switch">
          <button type="button" className={mode === 'login' ? 'active' : ''} onClick={() => setMode('login')}>Login</button>
          <button type="button" className={mode === 'register' ? 'active' : ''} onClick={() => setMode('register')}>Register</button>
        </div>

        {mode === 'login' && (
          <div className="login-split">
            <aside className="login-about">
              <h3>About SecureScope</h3>
              <p>SecureScope helps authorized users perform automated web reconnaissance and risk analysis.</p>
              <p>Our system scans these areas:</p>
              <ul>
                <li>Port Scan</li>
                <li>Subdomain Enumeration</li>
                <li>DNS Records Inspection</li>
                <li>SSL/TLS Configuration Check</li>
                <li>HTTP Security Headers Validation</li>
                <li>Technology Fingerprinting</li>
                <li>OSINT Metadata Collection</li>
                <li>Cookie Flags Check</li>
                <li>Directory Enumeration</li>
                <li>Admin Panel Exposure Probe</li>
                <li>Rate-Limit Behavior Probe</li>
                <li>Reflected XSS Probe</li>
                <li>SQLi Error Probe</li>
                <li>CSRF Token Hint Probe</li>
              </ul>
            </aside>
            <form className="auth-form login-form" onSubmit={submitLogin}>
              <label>Email</label>
              <input
                type="email"
                value={loginForm.email}
                onChange={(e) => setLoginForm((p) => ({ ...p, email: e.target.value }))}
                placeholder="admin@securescope.app"
                required
              />
              <label>Password</label>
              <input
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm((p) => ({ ...p, password: e.target.value }))}
                placeholder="Enter password"
                required
              />
              <button type="submit" className="primary-btn">Sign In</button>
            </form>
          </div>
        )}

        {mode === 'register' && (
          <form className="auth-form" onSubmit={submitRegister}>
            <label>Full Name</label>
            <input
              type="text"
              value={registerForm.full_name}
              onChange={(e) => setRegisterForm((p) => ({ ...p, full_name: e.target.value }))}
              placeholder="Your name"
              required
            />
            <label>Organization</label>
            <input
              type="text"
              value={registerForm.organization}
              onChange={(e) => setRegisterForm((p) => ({ ...p, organization: e.target.value }))}
              placeholder="Company or Institution"
              required
            />
            <label>Job Title</label>
            <input
              type="text"
              value={registerForm.job_title}
              onChange={(e) => setRegisterForm((p) => ({ ...p, job_title: e.target.value }))}
              placeholder="Security Analyst"
              required
            />
            <label>Work Phone</label>
            <input
              type="tel"
              value={registerForm.phone}
              onChange={(e) => setRegisterForm((p) => ({ ...p, phone: e.target.value }))}
              placeholder="e.g. +1 555 0100"
              required
            />
            <label>Legitimate Usage Purpose (minimum 20 chars)</label>
            <textarea
              value={registerForm.purpose}
              onChange={(e) => setRegisterForm((p) => ({ ...p, purpose: e.target.value }))}
              placeholder="Explain why you need this platform and what systems you are authorized to assess"
              minLength={20}
              required
            />
            <label>Email</label>
            <input
              type="email"
              value={registerForm.email}
              onChange={(e) => setRegisterForm((p) => ({ ...p, email: e.target.value }))}
              placeholder="analyst@example.com"
              required
            />
            <label>Password (minimum 12 chars)</label>
            <input
              type="password"
              value={registerForm.password}
              onChange={(e) => setRegisterForm((p) => ({ ...p, password: e.target.value }))}
              placeholder="Minimum 12 characters"
              minLength={12}
              required
            />
            <label>Role</label>
            <select
              value={registerForm.role}
              onChange={(e) => setRegisterForm((p) => ({ ...p, role: e.target.value }))}
            >
              {roles.map((role) => <option key={role} value={role}>{role}</option>)}
            </select>
            <button type="submit" className="primary-btn">Create Account</button>
          </form>
        )}

        {status && <p className="status-msg">{status}</p>}
        {error && <p className="error-msg">{error}</p>}
      </section>
    </div>
  )
}
