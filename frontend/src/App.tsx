import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './auth'
import { Layout } from './components/Layout'

const Dashboard = lazy(() => import('./pages/Dashboard').then((module) => ({ default: module.Dashboard })))
const Login = lazy(() => import('./pages/Login').then((module) => ({ default: module.Login })))
const Profile = lazy(() => import('./pages/Profile').then((module) => ({ default: module.Profile })))
const Traffic = lazy(() => import('./pages/Traffic').then((module) => ({ default: module.Traffic })))
const Users = lazy(() => import('./pages/Users').then((module) => ({ default: module.Users })))

function Protected(){const{user,loading}=useAuth();if(loading)return <div className="loading">Загрузка Xenoeye…</div>;return user?<Layout/>:<Navigate to="/login" replace/>}
export default function App(){return <Suspense fallback={<div className="loading">Загрузка Xenoeye…</div>}><Routes><Route path="/login" element={<Login/>}/><Route element={<Protected/>}><Route index element={<Dashboard/>}/><Route path="traffic" element={<Traffic/>}/><Route path="profile" element={<Profile/>}/><Route path="users" element={<Users/>}/></Route><Route path="*" element={<Navigate to="/"/>}/></Routes></Suspense>}
