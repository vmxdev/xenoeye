import { Plus, UserCheck, UserX } from 'lucide-react'
import { FormEvent, useEffect, useState } from 'react'
import { api } from '../api'
import type { TableInfo, User } from '../types'

export function Users() {
  const [users,setUsers]=useState<User[]>([]),[tables,setTables]=useState<TableInfo[]>([]),[open,setOpen]=useState(false),[error,setError]=useState('')
  const load=()=>Promise.all([api.get<User[]>('/users'),api.get<TableInfo[]>('/traffic/tables')]).then(([u,t])=>{setUsers(u.data);setTables(t.data)})
  useEffect(()=>{load()},[])
  const create=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();setError('');const form=new FormData(e.currentTarget);try{await api.post('/users',{email:form.get('email'),full_name:form.get('full_name'),password:form.get('password'),is_active:true,is_admin:form.get('is_admin')==='on',allowed_tables:form.getAll('allowed_tables')});setOpen(false);load()}catch(err:any){setError(err.response?.data?.detail||'Не удалось создать пользователя')}}
  const toggle=async(u:User)=>{await api.patch(`/users/${u.id}`,{is_active:!u.is_active});load()}
  return <div className="page"><header className="page-head"><div><span className="eyebrow">ACCESS CONTROL</span><h1>Пользователи</h1><p>Персональные кабинеты и доступ к объектам мониторинга</p></div><button className="primary-button small" onClick={()=>setOpen(true)}><Plus size={17}/>Новый пользователь</button></header>
    <section className="panel"><table><thead><tr><th>ПОЛЬЗОВАТЕЛЬ</th><th>РОЛЬ</th><th>ДОСТУП</th><th>СТАТУС</th><th/></tr></thead><tbody>{users.map(u=><tr key={u.id}><td><b>{u.full_name}</b><small>{u.email}</small></td><td><span className="role">{u.is_admin?'Администратор':'Аналитик'}</span></td><td>{u.allowed_tables.includes('*')?'Все таблицы':`${u.allowed_tables.length} источн.`}</td><td><span className={u.is_active?'active':'inactive'}>{u.is_active?'Активен':'Отключён'}</span></td><td><button className="icon-button" onClick={()=>toggle(u)}>{u.is_active?<UserX size={17}/>:<UserCheck size={17}/>}</button></td></tr>)}</tbody></table></section>
    {open&&<div className="modal-backdrop"><form className="modal" onSubmit={create}><div className="panel-head"><div><span className="eyebrow">NEW ACCOUNT</span><h2>Новый пользователь</h2></div><button type="button" className="icon-button" onClick={()=>setOpen(false)}>×</button></div><label>Имя<input name="full_name" required minLength={2}/></label><label>Email<input name="email" type="email" required/></label><label>Временный пароль<input name="password" type="password" required minLength={10}/></label><label className="check"><input name="is_admin" type="checkbox"/>Администратор</label><fieldset><legend>Доступные таблицы</legend><label className="check"><input name="allowed_tables" type="checkbox" value="*"/>Все текущие и будущие</label>{tables.map(t=><label className="check" key={t.name}><input name="allowed_tables" type="checkbox" value={t.name}/>{t.name}</label>)}</fieldset>{error&&<div className="form-error">{error}</div>}<button className="primary-button">Создать кабинет</button></form></div>}
  </div>
}

