import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { Point } from '../types'

const tick = (value: number) => value >= 1e9 ? `${(value/1e9).toFixed(1)}G` : value >= 1e6 ? `${(value/1e6).toFixed(1)}M` : value >= 1e3 ? `${(value/1e3).toFixed(0)}K` : `${value}`

export function TrafficChart({ data }: { data: Point[] }) {
  return <ResponsiveContainer width="100%" height={320}>
    <AreaChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
      <defs><linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#2dd4bf" stopOpacity={.38}/><stop offset="100%" stopColor="#2dd4bf" stopOpacity={0}/></linearGradient></defs>
      <CartesianGrid stroke="#193047" vertical={false}/>
      <XAxis dataKey="time" tickFormatter={(v) => new Date(v).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'})} stroke="#64809a" tickLine={false} axisLine={false}/>
      <YAxis tickFormatter={tick} stroke="#64809a" tickLine={false} axisLine={false}/>
      <Tooltip contentStyle={{background:'#0d1d2d',border:'1px solid #24415a',borderRadius:12}} labelFormatter={(v) => new Date(String(v)).toLocaleString('ru-RU')} formatter={(v) => tick(Number(v))}/>
      <Area type="monotone" dataKey="value" stroke="#2dd4bf" strokeWidth={2.4} fill="url(#trafficFill)"/>
    </AreaChart>
  </ResponsiveContainer>
}
