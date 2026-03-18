import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function LoginPage() {
  const navigate = useNavigate()
  const { login } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  const onSubmit = async (e) => {
    e.preventDefault()
    try {
      setError('')
      await login(email, password)
      navigate('/')
    } catch {
      setError('Login failed')
    }
  }

  return (
    <div className="login">
      <form onSubmit={onSubmit} className="card">
        <h2>Secure Login</h2>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" type="email" required />
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" required />
        <button type="submit">Sign In</button>
        {error && <p className="error">{error}</p>}
      </form>
    </div>
  )
}
