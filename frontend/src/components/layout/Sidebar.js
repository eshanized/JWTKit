import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import './layout.css';

const Sidebar = ({ isOpen }) => {
  const { isAuthenticated } = useAuth();
  
  const navItems = [
    {
      title: 'Core Tools',
      items: [
        { path: '/', icon: 'fa-tachometer-alt', label: 'Dashboard', badge: null },
        { path: '/decode', icon: 'fa-unlock-keyhole', label: 'JWT Decoder', badge: null },
        { path: '/verify', icon: 'fa-signature', label: 'Signature Verifier', badge: null },
        { path: '/modify', icon: 'fa-pen-to-square', label: 'Payload Editor', badge: null }
      ]
    },
    {
      title: 'Security Analysis',
      items: [
        { path: '/vulnerabilities', icon: 'fa-shield-virus', label: 'Vulnerability Scanner', badge: null },
        { path: '/security-patterns', icon: 'fa-magnifying-glass-chart', label: 'Pattern Detector', badge: null },
        { path: '/recommendations', icon: 'fa-list-check', label: 'Recommendations', badge: null },
        { path: '/attack-vectors', icon: 'fa-diagram-project', label: 'Attack Vectors', badge: { text: 'NEW', variant: 'success' } }
      ]
    },
    {
      title: 'Attack Simulation',
      items: [
        { path: '/attacks/algorithm-confusion', icon: 'fa-code-compare', label: 'Algorithm Confusion', badge: null },
        { path: '/attacks/brute-force', icon: 'fa-hammer', label: 'Brute Force Engine', badge: null },
        { path: '/tokens/fuzzer', icon: 'fa-random', label: 'Token Fuzzer', badge: null },
        { path: '/attack-simulator', icon: 'fa-bug', label: 'Attack Simulator', badge: { text: 'PRO', variant: 'warning' } }
      ]
    },
    {
      title: 'Utilities',
      items: [
        { path: '/tokens/test', icon: 'fa-vial', label: 'Token Tester', badge: null },
        { path: '/tokens/compare', icon: 'fa-code-compare', label: 'Token Comparison', badge: null },
        { path: '/tokens/history', icon: 'fa-history', label: 'Token History', badge: null },
        { path: '/keys', icon: 'fa-key', label: 'Key Manager', badge: null }
      ]
    }
  ];
  
  const adminItems = {
    title: 'Administration',
    items: [
      { path: '/analytics', icon: 'fa-chart-line', label: 'Attack Analytics', badge: null },
      { path: '/audit', icon: 'fa-clipboard-list', label: 'Audit Log', badge: null },
      { path: '/validation', icon: 'fa-check-circle', label: 'Validation Feedback', badge: { text: '3', variant: 'danger' } },
      { path: '/reports', icon: 'fa-file-alt', label: 'Report Generator', badge: null }
    ]
  };
  
  return (
    <aside className={`app-sidebar ${isOpen ? 'open' : 'closed'}`}>
      <nav className="sidebar-nav">
        {navItems.map((section, sectionIndex) => (
          <div className="nav-section" key={sectionIndex}>
            <h3 className="nav-section-title">{section.title}</h3>
            <ul className="nav-list">
              {section.items.map((item, itemIndex) => (
                <li className="nav-item" key={itemIndex}>
                  <NavLink 
                    to={item.path} 
                    className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                  >
                    <i className={`fas ${item.icon} nav-icon`}></i>
                    <span className="nav-label">{item.label}</span>
                    {item.badge && (
                      <span className={`nav-badge badge-${item.badge.variant}`}>
                        {item.badge.text}
                      </span>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
        
        {isAuthenticated && (
          <div className="nav-section">
            <h3 className="nav-section-title">{adminItems.title}</h3>
            <ul className="nav-list">
              {adminItems.items.map((item, itemIndex) => (
                <li className="nav-item" key={itemIndex}>
                  <NavLink 
                    to={item.path} 
                    className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                  >
                    <i className={`fas ${item.icon} nav-icon`}></i>
                    <span className="nav-label">{item.label}</span>
                    {item.badge && (
                      <span className={`nav-badge badge-${item.badge.variant}`}>
                        {item.badge.text}
                      </span>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        )}
      </nav>
      
      <div className="sidebar-footer">
        <div className="version">v2.0.0</div>
        <a href="https://github.com/eshanized/JWTKit" target="_blank" rel="noopener noreferrer" className="github-link">
          <i className="fab fa-github"></i>
        </a>
      </div>
    </aside>
  );
};

export default Sidebar; 