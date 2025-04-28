import React from 'react';
import { NavLink } from 'react-router-dom';
import './Layout.css';

const Sidebar = ({ isOpen }) => {
  const navItems = [
    { path: '/', icon: '🏠', label: 'Dashboard' },
    { path: '/decode', icon: '🔍', label: 'Decode JWT' },
    { path: '/verify', icon: '✓', label: 'Verify Signature' },
    { path: '/scan', icon: '🔒', label: 'Scan Vulnerabilities' },
    { path: '/edit', icon: '✏️', label: 'Edit Payload' }
  ];

  return (
    <aside className={`sidebar ${isOpen ? 'open' : 'closed'}`}>
      <nav className="sidebar-nav">
        <ul className="nav-list">
          {navItems.map((item, index) => (
            <li key={index} className="nav-item">
              <NavLink 
                to={item.path} 
                className={({ isActive }) => 
                  isActive ? 'nav-link active' : 'nav-link'
                }
                end={item.path === '/'}
              >
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <div className="sidebar-footer">
        <span className="version">v1.0.0</span>
      </div>
    </aside>
  );
};

export default Sidebar; 