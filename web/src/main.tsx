import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './App.css'

// Apply saved theme
const saved = localStorage.getItem('spectra-theme')
document.documentElement.setAttribute('data-theme', saved === 'light' ? 'light' : 'dark')

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
