import { Activity, Database, LogOut, Network, ShieldCheck, UserRound, Users } from 'lucide-react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth'

const nav = [
  { to: '/', label: 'Обзор', icon: Activity },
  { to: '/traffic', label: 'Аналитика', icon: Database },
  { to: '/profile', label: 'Профиль', icon: UserRound },
]

export function Layout() {
  const { user, logout } = useAuth()
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark"><Network size={22}/></span><span>XENOEYE<small>NETWORK INTELLIGENCE</small></span></div>
        <nav>
          {nav.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} end={to === '/'}><Icon size={18}/>{label}</NavLink>)}
          {user?.is_admin && <NavLink to="/users"><Users size={18}/>Пользователи</NavLink>}
        </nav>
        <div className="sidebar-foot">
          <div className="status"><ShieldCheck size={16}/><span>Система защищена<small>RBAC включён</small></span></div>
          <button className="ghost-button" onClick={logout}><LogOut size={17}/>Выйти</button>
        </div>
      </aside>
      <main className="main"><Outlet/></main>
    </div>
  )
}

