import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import './layout.css';

const Header = ({ toggleSidebar }) => {
  const { isAuthenticated, user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  
  return (
    <header className="app-header">
      <div className="header-left">
        <button 
          className="sidebar-toggle" 
          onClick={toggleSidebar}
          aria-label="Toggle Sidebar"
        >
          <i className="fas fa-bars"></i>
        </button>
        <div className="logo">
          <Link to="/">
            <img src="/logo.svg" alt="JWTKit Logo" className="logo-image" />
            <span className="logo-text">JWTKit</span>
          </Link>
        </div>
      </div>
      
      <div className="header-center">
        {!isAuthenticated && (
          <div className="guest-indicator">
            <i className="fas fa-info-circle"></i>
            <span>You're using JWTKit as a guest. All features are available but data won't be saved.</span>
          </div>
        )}
        <div className="search-bar">
          <i className="fas fa-search search-icon"></i>
          <input 
            type="search" 
            placeholder="Search tools, tokens, reports..." 
            className="search-input" 
          />
        </div>
      </div>
      
      <div className="header-right">
        <button 
          className="theme-toggle" 
          onClick={toggleTheme}
          aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
        >
          <i className={`fas fa-${theme === 'light' ? 'moon' : 'sun'}`}></i>
        </button>
        
        <div className="notifications">
          <button className="notification-button" aria-label="View notifications">
            <i className="fas fa-bell"></i>
            <span className="notification-badge">2</span>
          </button>
        </div>
        
        {isAuthenticated ? (
          <div className="user-menu">
            <button className="user-button">
              <div className="avatar">
                {user?.username?.charAt(0).toUpperCase() || 'U'}
              </div>
              <span className="username">{user?.username || 'User'}</span>
              <i className="fas fa-chevron-down"></i>
            </button>
            
            <div className="dropdown-menu">
              <Link to="/profile" className="dropdown-item">
                <i className="fas fa-user"></i> Profile
              </Link>
              <Link to="/settings" className="dropdown-item">
                <i className="fas fa-cog"></i> Settings
              </Link>
              <div className="dropdown-divider"></div>
              <button onClick={logout} className="dropdown-item">
                <i className="fas fa-sign-out-alt"></i> Logout
              </button>
            </div>
          </div>
        ) : (
          <div className="auth-buttons">
            <Link to="/login" className="btn btn-outline">Login</Link>
            <Link to="/register" className="btn btn-primary">Register</Link>
          </div>
        )}
      </div>
    </header>
  );
};

export default Header; 