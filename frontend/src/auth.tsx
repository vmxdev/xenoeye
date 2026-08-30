import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api } from './api'
import type { User } from './types'

interface AuthValue {
  user: User | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!localStorage.getItem('xe_token')) { setLoading(false); return }
    api.get<User>('/auth/me').then(({ data }) => setUser(data)).finally(() => setLoading(false))
  }, [])

  const login = async (email: string, password: string) => {
    const body = new URLSearchParams({ username: email, password })
    const { data } = await api.post('/auth/token', body, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    localStorage.setItem('xe_token', data.access_token)
    const profile = await api.get<User>('/auth/me')
    setUser(profile.data)
  }

  const logout = () => { localStorage.removeItem('xe_token'); setUser(null) }
  return <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside AuthProvider')
  return value
}

