import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App as AntApp, ConfigProvider, theme } from 'antd'
import 'antd/dist/reset.css'
import { FeatureApp } from './app/FeatureApp.jsx'
import './styles.css'
import './material-inputs.css'
import './light-styles.css'

const darkTheme = {
  algorithm: theme.darkAlgorithm,
  token: {
    colorPrimary: '#62d9ff',
    colorInfo: '#62d9ff',
    colorSuccess: '#65d49d',
    colorWarning: '#f1b45b',
    colorError: '#ff7373',
    colorBgBase: '#080b0e',
    colorBgContainer: '#11161a',
    colorBgElevated: '#171d22',
    colorBorder: '#2b343b',
    colorBorderSecondary: '#222a30',
    borderRadius: 7,
    borderRadiusLG: 9,
    fontFamily: "Inter, 'Microsoft YaHei', ui-sans-serif, system-ui, sans-serif",
  },
  components: {
    Layout: { bodyBg: '#080b0e', headerBg: '#101519', siderBg: '#0e1317' },
    Menu: { darkItemBg: '#0e1317', darkItemSelectedBg: '#1c3039', darkItemSelectedColor: '#8ce8ff' },
  },
}

const lightTheme = {
  algorithm: theme.defaultAlgorithm,
  token: {
    colorPrimary: '#1677b8', colorInfo: '#1677b8', colorSuccess: '#16845b', colorWarning: '#ad6b00', colorError: '#c43d3d',
    colorBgBase: '#f4f7fb', colorBgContainer: '#ffffff', colorBgElevated: '#ffffff', colorBorder: '#d8e1ea', colorBorderSecondary: '#e8eef4',
    colorText: '#1d2a38', colorTextSecondary: '#5c6c7d', borderRadius: 9, borderRadiusLG: 12,
    fontFamily: "Inter, 'Microsoft YaHei', ui-sans-serif, system-ui, sans-serif",
  },
  components: {
    Layout: { bodyBg: '#f4f7fb', headerBg: 'rgba(255,255,255,.9)', siderBg: '#ffffff' },
    Menu: { itemBg: '#ffffff', itemSelectedBg: '#e8f4fc', itemSelectedColor: '#12689e', itemColor: '#435365' },
  },
}

function MainEntry() {
  const [themeMode, setThemeMode] = useState(() => {
    const requested = new URLSearchParams(window.location.search).get('theme')
    if (requested === 'light' || requested === 'dark') return requested
    return window.localStorage.getItem('sec-theme-mode') === 'light' ? 'light' : 'dark'
  })
  useEffect(() => {
    document.body.classList.toggle('light-theme', themeMode === 'light')
    document.documentElement.style.colorScheme = themeMode
    document.body.dataset.theme = themeMode
    window.localStorage.setItem('sec-theme-mode', themeMode)
  }, [themeMode])
  const toggleTheme = () => setThemeMode((mode) => mode === 'light' ? 'dark' : 'light')

  return <React.StrictMode>
    <ConfigProvider theme={themeMode === 'light' ? lightTheme : darkTheme}>
      <AntApp>
        <BrowserRouter><FeatureApp themeMode={themeMode} onToggleTheme={toggleTheme} /></BrowserRouter>
      </AntApp>
    </ConfigProvider>
  </React.StrictMode>
}

createRoot(document.getElementById('root')).render(<MainEntry />)
