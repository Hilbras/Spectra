import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

const saved = localStorage.getItem('spectra-theme')
document.documentElement.classList.toggle('dark', saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches))

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
