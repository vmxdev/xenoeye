export interface User {
  id: number
  email: string
  full_name: string
  is_active: boolean
  is_admin: boolean
  allowed_tables: string[]
  created_at: string
}

export interface ColumnInfo { name: string; data_type: string; numeric: boolean }
export interface TableInfo { name: string; columns: ColumnInfo[] }
export interface Summary {
  bytes: number
  packets: number
  flows: number
  active_tables: number
  last_data_at: string | null
}
export interface Point { time: string; value: number }

