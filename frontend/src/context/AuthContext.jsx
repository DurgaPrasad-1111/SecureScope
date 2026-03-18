import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import api from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)

  const login = async (email, password) => {
    const { data } = await api.post('/auth/login', { email, password })
    localStorage.setItem('access_token', data.access_token)
    localStorage.setItem('refresh_token', data.refresh_token)
    localStorage.setItem('csrf_token', data.csrf_token)
    await loadUser()
  }

  const register = async (payload) => {
    await api.post('/auth/register', payload)
  }

  const logout = async () => {
    const refresh = localStorage.getItem('refresh_token')
    if (refresh) {
      try {
        await api.post('/auth/logout', { refresh_token: refresh })
      } catch {
      }
    }
    localStorage.clear()
    setUser(null)
  }

  const loadUser = async () => {
    try {
      const { data } = await api.get('/users/me')
      setUser(data)
    } catch {
      setUser(null)
    }
  }

  useEffect(() => {
    if (localStorage.getItem('access_token')) loadUser()
  }, [])

  const value = useMemo(() => ({ user, login, register, logout, loadUser }), [user])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  return useContext(AuthContext)
}
