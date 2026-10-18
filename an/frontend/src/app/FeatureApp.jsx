import React, { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { AlertOutlined, AuditOutlined, BulbOutlined, ClusterOutlined, DashboardOutlined, DatabaseOutlined, FileTextOutlined, MenuFoldOutlined, MenuUnfoldOutlined, MoonOutlined, RobotOutlined, ToolOutlined, TeamOutlined } from '@ant-design/icons'
import { Button, Layout, Menu, Tag } from 'antd'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { health } from '../api.js'
import { ControlStarfield } from './ControlStarfield.jsx'

const lazyPage = (loader, exportName) => lazy(() => loader().then((module) => ({ default: module[exportName] })))
const AuditReplayPage = lazyPage(() => import('./AuditReplayPage.jsx'), 'AuditReplayPage')
const ModelUsagePage = lazyPage(() => import('./ModelUsagePage.jsx'), 'ModelUsagePage')
const WorkbenchPage = lazyPage(() => import('./WorkbenchPage.jsx'), 'WorkbenchPage')
const ExperienceLibraryPage = lazyPage(() => import('./ExperienceLibraryPage.jsx'), 'ExperienceLibraryPage')
const AssetLibraryPage = lazyPage(() => import('./AssetLibraryPage.jsx'), 'AssetLibraryPage')
const PromptCatalogPage = lazyPage(() => import('./PromptCatalogPage.jsx'), 'PromptCatalogPage')
const McpRegistryPage = lazyPage(() => import('./McpRegistryPage.jsx'), 'McpRegistryPage')
const IncidentResponsePage = lazyPage(() => import('./IncidentResponsePage.jsx'), 'IncidentResponsePage')
const CockpitPage = lazyPage(() => import('./CockpitPage.jsx'), 'CockpitPage')

const { Header, Sider, Content } = Layout
const routes = { '/cockpit': ['安全运营驾驶舱', <DashboardOutlined />], '/workbench': ['任务编排', <TeamOutlined />], '/audit': ['审计与拦截', <AuditOutlined />], '/experiences': ['经验学习库', <DatabaseOutlined />], '/assets': ['跨任务资产库', <ClusterOutlined />], '/incident-response': ['应急响应', <AlertOutlined />], '/models': ['模型与用量', <RobotOutlined />], '/prompts': ['Prompt 目录', <FileTextOutlined />], '/mcp': ['MCP 工具清单', <ToolOutlined />] }

export function FeatureApp({ themeMode = 'dark', onToggleTheme }) {
  const navigate = useNavigate(); const location = useLocation(); const [collapsed, setCollapsed] = useState(false); const [mobileOpen, setMobileOpen] = useState(false); const [isNarrow, setIsNarrow] = useState(() => window.matchMedia('(max-width: 900px)').matches); const [backend, setBackend] = useState(null)
  const logoSrc = themeMode === 'light' ? '/secmind-logo.png' : '/secmind-logo-dark.png'
  const active = location.pathname === '/' || location.pathname.startsWith('/cockpit') || location.pathname === '/dashboard' ? '/cockpit' : location.pathname.startsWith('/audit') ? '/audit' : location.pathname.startsWith('/experiences') ? '/experiences' : location.pathname.startsWith('/assets') ? '/assets' : location.pathname.startsWith('/incident-response') ? '/incident-response' : location.pathname.startsWith('/models') ? '/models' : location.pathname.startsWith('/prompts') ? '/prompts' : location.pathname.startsWith('/mcp') ? '/mcp' : '/workbench'
  const [title, titleIcon] = routes[active]
  useEffect(() => setMobileOpen(false), [location.pathname])
  useEffect(() => { const query = window.matchMedia('(max-width: 900px)'); const update = () => setIsNarrow(query.matches); update(); query.addEventListener?.('change', update); return () => query.removeEventListener?.('change', update) }, [])
  useEffect(() => { let live = true; const check = () => health().then((value) => live && setBackend(value)).catch(() => live && setBackend(null)); check(); const timer = setInterval(check, 10000); return () => { live = false; clearInterval(timer) } }, [])
  const items = useMemo(() => [
    { type: 'group', label: '安全运营', children: [
      { key: '/cockpit', icon: <DashboardOutlined />, label: '安全运营驾驶舱' },
      { key: '/workbench', icon: <TeamOutlined />, label: '任务编排' },
      { key: '/audit', icon: <AuditOutlined />, label: '审计与拦截' },
      { key: '/assets', icon: <ClusterOutlined />, label: '跨任务资产库' },
      { key: '/experiences', icon: <DatabaseOutlined />, label: '经验学习库' },
      { key: '/incident-response', icon: <AlertOutlined />, label: '应急响应' },
    ] },
    { type: 'group', label: '系统能力', children: [
      { key: '/models', icon: <RobotOutlined />, label: '模型与用量' },
      { key: '/prompts', icon: <FileTextOutlined />, label: 'Prompt 目录' },
      { key: '/mcp', icon: <ToolOutlined />, label: 'MCP 工具清单' },
    ] },
  ], [])

  const toggleSidebar = () => window.matchMedia('(max-width: 900px)').matches ? setMobileOpen((open) => !open) : setCollapsed((value) => !value)
  const selectPage = (key) => { setMobileOpen(false); navigate(key) }

  return <Layout className={`feature-shell ${collapsed ? 'is-collapsed' : ''} ${mobileOpen ? 'is-mobile-open' : ''}`}>
    <ControlStarfield />
    <button className="sidebar-backdrop" type="button" onClick={() => setMobileOpen(false)} aria-label="关闭导航" />
    <Sider className="feature-sidebar" width={236} collapsedWidth={72} collapsed={collapsed} trigger={null}>
      <button className="sidebar-title" type="button" onClick={() => selectPage('/cockpit')} aria-label="打开安全运营驾驶舱" title="打开安全运营驾驶舱"><img className="sidebar-logo" src={logoSrc} alt="SecMind" /></button>
      <Menu mode="inline" selectedKeys={[active]} items={items} onClick={({ key }) => selectPage(key)} />
      <div className="sidebar-bottom">
        <div className="sidebar-foot"><i className={backend ? 'is-online' : ''} /><span>{backend ? '统一平台 API 在线' : '统一平台 API 离线'}</span></div>
        {onToggleTheme && <button className="theme-toggle" type="button" onClick={onToggleTheme} aria-label={themeMode === 'light' ? '切换深色主题' : '切换浅色主题'} title={themeMode === 'light' ? '切换深色主题' : '切换浅色主题'}>
          <span className="theme-toggle-icon">{themeMode === 'light' ? <MoonOutlined /> : <BulbOutlined />}</span>
          <span className="theme-toggle-label">{themeMode === 'light' ? '深色主题' : '浅色主题'}</span>
        </button>}
      </div>
    </Sider>
    <Layout className="feature-main">
      <Header className="feature-header"><div><Button type="text" icon={(isNarrow ? !mobileOpen : collapsed) ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={toggleSidebar} aria-label="切换导航" /><span className="header-module">{titleIcon}<b>{title}</b></span></div><div className="header-status"><Tag className="semantic-status-tag" color={backend ? 'success' : 'error'}>{backend ? '后端在线' : '后端离线'}</Tag>{backend?.demo_mode && <Tag color="gold">DEMO</Tag>}<span>{new Date().toLocaleDateString('zh-CN')}</span></div></Header>
      <Content className="feature-content"><Suspense fallback={<div className="route-loading" role="status">正在加载页面…</div>}><Routes><Route path="/cockpit" element={<CockpitPage />} /><Route path="/dashboard" element={<CockpitPage />} /><Route path="/workbench" element={<WorkbenchPage />} /><Route path="/audit" element={<AuditReplayPage />} /><Route path="/audit/:runId" element={<AuditReplayPage />} /><Route path="/assets/:assetId?" element={<AssetLibraryPage />} /><Route path="/experiences" element={<ExperienceLibraryPage />} /><Route path="/incident-response" element={<IncidentResponsePage />} /><Route path="/models" element={<ModelUsagePage />} /><Route path="/prompts" element={<PromptCatalogPage />} /><Route path="/mcp" element={<McpRegistryPage />} /><Route path="*" element={<Navigate to="/cockpit" replace />} /></Routes></Suspense></Content>
    </Layout>
  </Layout>
}
