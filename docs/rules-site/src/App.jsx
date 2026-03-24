import React, { useState, useEffect } from 'react'
import { HashRouter as Router, Routes, Route, Link, useParams, useLocation } from 'react-router-dom'
import { Search, ChevronRight, ChevronDown, AlertTriangle, Info, Shield, Zap, Home, ExternalLink, Book, Layers, Box, Terminal, GitBranch, Settings } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import rulesData from './data/rules.json'
import docsData from './data/docs.json'

// --- Components ---

const SeverityBadge = ({ severity }) => (
  <span className={`severity-badge severity-${severity.toLowerCase()}`}>
    {severity}
  </span>
)

const DimensionIcon = ({ dimension, size = 18 }) => {
  switch (dimension.toLowerCase()) {
    case 'security': return <Shield size={size} className="accent-red" />
    case 'performance': return <Zap size={size} className="accent-yellow" />
    case 'quality': return <Info size={size} className="accent-blue" />
    case 'reliability': return <AlertTriangle size={size} className="accent-purple" />
    case 'cost': return <Box size={size} className="accent-green" />
    case 'compliance': return <Shield size={size} className="accent-blue" />
    default: return <AlertTriangle size={size} className="accent-purple" />
  }
}

const RecursiveNavItem = ({ item, depth = 0 }) => {
  const [isOpen, setIsOpen] = useState(depth === 0)
  const location = useLocation()
  
  if (item.children) {
    return (
      <div className="nav-group">
        <button 
          onClick={() => setIsOpen(!isOpen)}
          style={{ 
            display: 'flex', 
            alignItems: 'center', 
            width: '100%',
            padding: '8px 12px',
            background: 'none',
            border: 'none',
            color: 'var(--text-secondary)',
            fontSize: '13px',
            fontWeight: '600',
            cursor: 'pointer',
            gap: '8px'
          }}
        >
          {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          {item.title}
        </button>
        {isOpen && (
          <div className="nested-nav">
            {item.children.map((child, i) => (
              <RecursiveNavItem key={i} item={child} depth={depth + 1} />
            ))}
          </div>
        )}
      </div>
    )
  }

  const isActive = location.pathname === `/docs/${item.path}`
  return (
    <Link 
      to={`/docs/${item.path}`}
      className={`nav-link ${isActive ? 'active' : ''}`}
      style={{ 
        display: 'block',
        padding: '6px 12px',
        fontSize: '13px',
        color: isActive ? 'var(--accent-blue)' : 'var(--text-secondary)',
        textDecoration: 'none',
        borderRadius: '4px'
      }}
    >
      {item.title}
    </Link>
  )
}

const Sidebar = () => {
  const [searchTerm, setSearchTerm] = useState('')
  const [activeTab, setActiveTab] = useState('docs') // 'docs' or 'rules'
  
  const filteredRules = rulesData.flat.filter(r => 
    r.id.toLowerCase().includes(searchTerm.toLowerCase()) || 
    r.name.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const groupedFilteredRules = {}
  filteredRules.forEach(r => {
    if (!groupedFilteredRules[r.dimension]) groupedFilteredRules[r.dimension] = []
    groupedFilteredRules[r.dimension].push(r)
  })

  return (
    <div className="sidebar">
      <div className="search-bar">
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '16px', gap: '8px' }}>
          <img src="/slowql-logo.svg" alt="SlowQL" style={{ width: '24px' }} />
          <h2 style={{ fontSize: '18px', fontWeight: '700' }}>SlowQL</h2>
        </div>
        
        <div style={{ display: 'flex', gap: '4px', marginBottom: '16px', background: 'var(--bg-tertiary)', padding: '4px', borderRadius: '8px' }}>
          <button 
            onClick={() => setActiveTab('docs')}
            style={{ 
              flex: 1, padding: '6px', borderRadius: '6px', border: 'none', fontSize: '12px', fontWeight: '600',
              background: activeTab === 'docs' ? 'var(--glass-bg)' : 'transparent',
              color: activeTab === 'docs' ? 'var(--text-primary)' : 'var(--text-secondary)',
              cursor: 'pointer'
            }}
          >
            Docs
          </button>
          <button 
            onClick={() => setActiveTab('rules')}
            style={{ 
              flex: 1, padding: '6px', borderRadius: '6px', border: 'none', fontSize: '12px', fontWeight: '600',
              background: activeTab === 'rules' ? 'var(--glass-bg)' : 'transparent',
              color: activeTab === 'rules' ? 'var(--text-primary)' : 'var(--text-secondary)',
              cursor: 'pointer'
            }}
          >
            Rules
          </button>
        </div>

        <div style={{ position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: '12px', top: '10px', color: 'var(--text-secondary)' }} />
          <input 
            className="search-input" 
            style={{ paddingLeft: '40px', height: '36px', fontSize: '13px' }}
            placeholder={`Search ${activeTab}...`} 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>
      
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 12px 24px' }}>
        {activeTab === 'docs' ? (
          <div>
            {docsData.map((item, i) => (
              <RecursiveNavItem key={i} item={item} />
            ))}
          </div>
        ) : (
          <div>
            {Object.entries(groupedFilteredRules).map(([dimension, rules]) => (
              <div key={dimension} style={{ marginBottom: '20px' }}>
                <div className="nav-section-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <DimensionIcon dimension={dimension} size={12} />
                  {dimension}
                </div>
                {rules.map(rule => (
                  <Link 
                    to={`/rules/${rule.id}`} 
                    key={rule.id}
                    className="nav-link"
                    style={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      padding: '8px 12px', 
                      borderRadius: '6px',
                      fontSize: '13px',
                      color: 'var(--text-secondary)',
                      marginBottom: '2px',
                      textDecoration: 'none'
                    }}
                  >
                    <span style={{ fontFamily: 'JetBrains Mono', marginRight: '8px', fontSize: '11px', opacity: 0.6 }}>{rule.id.split('-').pop()}</span>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rule.name}</span>
                  </Link>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

const MarkdownPage = () => {
  const { "*": path } = useParams()
  
  const findPage = (items, targetPath) => {
    for (const item of items) {
      if (item.path === targetPath) return item
      if (item.children) {
        const found = findPage(item.children, targetPath)
        if (found) return found
      }
    }
    return null
  }

  const page = findPage(docsData, path)

  if (!page) return <div className="main-content">Page not found: {path}</div>

  return (
    <motion.div 
      key={path}
      initial={{ opacity: 0, x: 10 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -10 }}
      className="main-content"
    >
      <div className="markdown-body">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>
          {page.content}
        </ReactMarkdown>
      </div>
    </motion.div>
  )
}

const RuleDetail = () => {
  const { id } = useParams()
  const rule = rulesData.flat.find(r => r.id === id)

  if (!rule) return <div className="main-content">Rule not found.</div>

  const badExample = rule.examples[0] || "-- No example available yet"
  const goodExample = rule.examples[1] || "-- No example available yet"

  return (
    <motion.div 
      key={id}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      className="main-content"
    >
      <div className="rule-header">
        <div className="rule-id">{rule.id}</div>
        <h1 className="rule-title">{rule.name}</h1>
        <div style={{ display: 'flex', gap: '8px' }}>
          <SeverityBadge severity={rule.severity} />
          <div className="severity-badge" style={{ background: 'var(--glass-bg)', color: 'var(--accent-blue)', borderColor: 'var(--glass-border)' }}>
            {rule.dimension}
          </div>
        </div>
      </div>

      <section className="rule-section">
        <p style={{ fontSize: '18px', color: 'var(--text-primary)', marginBottom: '24px' }}>{rule.description}</p>
        
        {rule.rationale && (
          <div className="glass" style={{ padding: '24px', marginBottom: '32px' }}>
            <h3 style={{ fontSize: '16px', marginBottom: '12px', color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Info size={18} /> Rationale
            </h3>
            <p style={{ color: 'var(--text-secondary)' }}>{rule.rationale}</p>
          </div>
        )}

        {rule.impact && (
          <div className="glass" style={{ padding: '24px', borderLeft: '4px solid var(--accent-red)', marginBottom: '32px' }}>
            <h3 style={{ fontSize: '16px', marginBottom: '12px', color: 'var(--accent-red)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Zap size={18} /> Impact
            </h3>
            <p style={{ color: 'var(--text-secondary)' }}>{rule.impact}</p>
          </div>
        )}
      </section>

      <section className="rule-section">
        <h2 className="section-title">Examples</h2>
        <div className="example-container">
          <div className="example-box example-bad glass">
            <div className="example-label">❌ Bad Snippet</div>
            <div className="example-code">{badExample}</div>
          </div>
          <div className="example-box example-good glass">
            <div className="example-label">✅ Good Snippet</div>
            <div className="example-code">{goodExample}</div>
          </div>
        </div>
      </section>

      {rule.fix_guidance && (
        <section className="rule-section">
          <h2 className="section-title">Remediation</h2>
          <div className="glass" style={{ padding: '24px' }}>
            <p style={{ lineHeight: '1.6' }}>{rule.fix_guidance}</p>
          </div>
        </section>
      )}

      {rule.references && rule.references.length > 0 && (
        <section className="rule-section">
          <h2 className="section-title">References</h2>
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {rule.references.map((ref, i) => (
              <li key={i} style={{ marginBottom: '12px' }}>
                <a href={ref} target="_blank" rel="noopener noreferrer" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-blue)', textDecoration: 'none' }}>
                  <ExternalLink size={16} /> {ref}
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}
    </motion.div>
  )
}

const HomeView = () => (
  <div className="main-content" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', minHeight: '80vh' }}>
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5 }}
      style={{ textAlign: 'center' }}
    >
      <div style={{ display: 'inline-flex', padding: '8px 16px', background: 'var(--glass-bg)', borderRadius: '20px', border: '1px solid var(--glass-border)', color: 'var(--accent-blue)', fontSize: '12px', fontWeight: '700', marginBottom: '24px', letterSpacing: '1px' }}>
        ENTERPRISE STATIC ANALYZER
      </div>
      <h1 style={{ fontSize: '72px', fontWeight: '900', marginBottom: '24px', background: 'linear-gradient(135deg, #fff 0%, #2f81f7 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', letterSpacing: '-2px' }}>
        The SlowQL Hub
      </h1>
      <p style={{ fontSize: '22px', color: 'var(--text-secondary)', maxWidth: '700px', margin: '0 auto 56px', lineHeight: '1.6' }}>
        The definitive guide to high-performance, secure, and cost-effective SQL. 
        Migrated from legacy documentation to a premium interactive experience.
      </p>
      
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px', maxWidth: '900px', margin: '0 auto' }}>
        {[
          { icon: <Zap />, title: 'Performance', count: rulesData.grouped['performance']?.length || 0 },
          { icon: <Shield />, title: 'Security', count: rulesData.grouped['security']?.length || 0 },
          { icon: <Box />, title: 'Cost', count: rulesData.grouped['cost']?.length || 0 },
          { icon: <Info />, title: 'Quality', count: rulesData.grouped['quality']?.length || 0 },
          { icon: <AlertTriangle />, title: 'Reliability', count: rulesData.grouped['reliability']?.length || 0 },
          { icon: <Shield />, title: 'Compliance', count: rulesData.grouped['compliance']?.length || 0 },
        ].map((stat, i) => (
          <div key={i} className="glass" style={{ padding: '24px', textAlign: 'left' }}>
            <div style={{ color: 'var(--accent-blue)', marginBottom: '16px' }}>{stat.icon}</div>
            <h3 style={{ fontSize: '14px', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '4px' }}>{stat.title}</h3>
            <p style={{ fontSize: '24px', fontWeight: '800' }}>{stat.count} Rules</p>
          </div>
        ))}
      </div>
    </motion.div>
  </div>
)

function App() {
  return (
    <Router>
      <div className="layout">
        <Sidebar />
        <div style={{ flex: 1, height: '100vh', overflowY: 'auto' }}>
          <AnimatePresence mode="wait">
            <Routes>
              <Route path="/" element={<HomeView />} />
              <Route path="/docs/*" element={<MarkdownPage />} />
              <Route path="/rules/:id" element={<RuleDetail />} />
            </Routes>
          </AnimatePresence>
        </div>
      </div>
    </Router>
  )
}

export default App
