import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Audit } from './pages/Audit'
import { Findings } from './pages/Findings'
import { History } from './pages/History'
import { Projects } from './pages/Projects'
import { Settings } from './pages/Settings'
import { Health } from './pages/Health'
import { Benchmarks } from './pages/Benchmarks'

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/history" element={<History />} />
          <Route path="/projects" element={<Projects />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/health" element={<Health />} />
          <Route path="/benchmarks" element={<Benchmarks />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
