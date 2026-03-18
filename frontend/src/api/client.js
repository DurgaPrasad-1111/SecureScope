import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api/v1',
  timeout: 120000,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  const csrf = localStorage.getItem('csrf_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  if (csrf) config.headers['X-CSRF-Token'] = csrf
  return config
})

export default api
