import { Eye, EyeOff, Network } from 'lucide-react'
import { FormEvent, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth'

export function Login() {
  const { user, login } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (user) return <Navigate to="/" replace/>
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError('')
    try { await login(email, password) } catch { setError('Проверьте email и пароль') } finally { setBusy(false) }
  }
  return <div className="login-page">
    <div className="login-glow"/><section className="login-panel">
      <div className="login-brand"><span className="brand-mark large"><Network size={30}/></span><div><strong>XENOEYE</strong><small>NETWORK INTELLIGENCE</small></div></div>
      <div className="login-copy"><span className="eyebrow">SECURE ACCESS</span><h1>Сеть под контролем.<br/><em>В реальном времени.</em></h1><p>Единая точка наблюдения за NetFlow, IPFIX и sFlow с персональным доступом к данным.</p></div>
      <div className="signal-card"><div className="signal-wave"/><span>LIVE TELEMETRY</span><b>Защищённый канал</b></div>
    </section>
    <section className="login-form-wrap"><form className="login-form" onSubmit={submit}>
      <h2>Вход в кабинет</h2><p>Используйте вашу корпоративную учётную запись</p>
      <label>Email<input type="email" value={email} onChange={(e)=>setEmail(e.target.value)} placeholder="name@company.ru" required autoFocus/></label>
      <label>Пароль<div className="password"><input type={show?'text':'password'} value={password} onChange={(e)=>setPassword(e.target.value)} required/><button type="button" onClick={()=>setShow(!show)}>{show?<EyeOff size={18}/>:<Eye size={18}/>}</button></div></label>
      {error && <div className="form-error">{error}</div>}
      <button className="primary-button" disabled={busy}>{busy?'Подключение…':'Войти в систему'}</button>
      <small className="security-note">Доступ контролируется администратором системы</small>
    </form></section>
  </div>
}

