import { Activity, Boxes, Clock3, Database, RefreshCw } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { TrafficChart } from '../components/TrafficChart'
import type { Point, Summary, TableInfo } from '../types'

const compact = (n:number) => new Intl.NumberFormat('ru-RU',{notation:'compact',maximumFractionDigits:1}).format(n)

export function Dashboard() {
  const { user } = useAuth()
  const [summary,setSummary]=useState<Summary|null>(null)
  const [tables,setTables]=useState<TableInfo[]>([])
  const [selected,setSelected]=useState('')
  const [series,setSeries]=useState<Point[]>([])
  const load = async () => {
    const [s,t]=await Promise.all([api.get<Summary>('/traffic/summary'),api.get<TableInfo[]>('/traffic/tables')])
    setSummary(s.data); setTables(t.data)
    const table=selected||t.data.find(x=>x.columns.some(c=>c.name==='octets'))?.name||t.data[0]?.name||''
    setSelected(table)
    if(table){const metric=t.data.find(x=>x.name===table)?.columns.some(c=>c.name==='octets')?'octets':t.data.find(x=>x.name===table)?.columns.find(c=>c.numeric)?.name; if(metric){const q=await api.get<Point[]>('/traffic/series',{params:{table,metric,bucket:'5m'}});setSeries(q.data)}}
  }
  useEffect(()=>{load()},[])
  useEffect(()=>{if(selected) load()},[selected])
  return <div className="page">
    <header className="page-head"><div><span className="eyebrow">OPERATIONS OVERVIEW</span><h1>Добрый день, {user?.full_name.split(' ')[0]}</h1><p>Сводка сетевой телеметрии за последние 24 часа</p></div><button className="outline-button" onClick={load}><RefreshCw size={16}/>Обновить</button></header>
    <section className="metrics-grid">
      <article className="metric"><span><Database size={19}/></span><small>ОБЪЁМ ТРАФИКА</small><strong>{compact(summary?.bytes||0)} <i>байт</i></strong><p>По доступным объектам</p></article>
      <article className="metric"><span><Activity size={19}/></span><small>ПАКЕТЫ</small><strong>{compact(summary?.packets||0)}</strong><p>Агрегировано коллектором</p></article>
      <article className="metric"><span><Boxes size={19}/></span><small>ЗАПИСИ</small><strong>{compact(summary?.flows||0)}</strong><p>Строк временных рядов</p></article>
      <article className="metric"><span><Clock3 size={19}/></span><small>ИСТОЧНИКИ</small><strong>{summary?.active_tables||0}</strong><p>{summary?.last_data_at?`Данные: ${new Date(summary.last_data_at).toLocaleTimeString('ru-RU')}`:'Ожидание данных'}</p></article>
    </section>
    <section className="panel chart-panel"><div className="panel-head"><div><span className="eyebrow">TRAFFIC DYNAMICS</span><h2>Динамика трафика</h2></div><select value={selected} onChange={(e)=>setSelected(e.target.value)}>{tables.map(t=><option key={t.name}>{t.name}</option>)}</select></div>{series.length?<TrafficChart data={series}/>:<div className="empty">Нет данных для построения графика</div>}</section>
  </div>
}

