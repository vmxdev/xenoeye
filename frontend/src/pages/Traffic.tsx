import { Search } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../api'
import { TrafficChart } from '../components/TrafficChart'
import type { Point, TableInfo } from '../types'

export function Traffic() {
  const [tables,setTables]=useState<TableInfo[]>([]),[table,setTable]=useState(''),[metric,setMetric]=useState(''),[data,setData]=useState<Point[]>([])
  useEffect(()=>{api.get<TableInfo[]>('/traffic/tables').then(({data})=>{setTables(data);setTable(data[0]?.name||'')})},[])
  useEffect(()=>{const t=tables.find(x=>x.name===table);setMetric(t?.columns.find(c=>c.name==='octets')?.name||t?.columns.find(c=>c.numeric)?.name||'')},[table,tables])
  const run=async()=>{if(table&&metric){const r=await api.get<Point[]>('/traffic/series',{params:{table,metric,bucket:'5m'}});setData(r.data)}}
  useEffect(()=>{run()},[metric])
  const current=tables.find(x=>x.name===table)
  return <div className="page"><header className="page-head"><div><span className="eyebrow">FLOW EXPLORER</span><h1>Аналитика трафика</h1><p>Исследуйте доступные временные ряды Xenoeye</p></div></header>
    <section className="panel filters"><label>Таблица<select value={table} onChange={e=>setTable(e.target.value)}>{tables.map(t=><option key={t.name}>{t.name}</option>)}</select></label><label>Метрика<select value={metric} onChange={e=>setMetric(e.target.value)}>{current?.columns.filter(c=>c.numeric).map(c=><option key={c.name}>{c.name}</option>)}</select></label><button className="primary-button small" onClick={run}><Search size={17}/>Построить</button></section>
    <section className="panel chart-panel"><div className="panel-head"><div><span className="eyebrow">{table||'NO DATA'}</span><h2>{metric||'Метрика не выбрана'}</h2></div></div>{data.length?<TrafficChart data={data}/>:<div className="empty">Выберите источник с накопленными данными</div>}</section>
    <section className="panel"><div className="panel-head"><div><span className="eyebrow">SCHEMA</span><h2>Поля источника</h2></div></div><div className="chips">{current?.columns.map(c=><span key={c.name}>{c.name}<small>{c.data_type}</small></span>)}</div></section>
  </div>
}

