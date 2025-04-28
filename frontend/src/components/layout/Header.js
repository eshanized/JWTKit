import React from 'react';
import { Link } from 'react-router-dom';
import './Layout.css';

const Header = ({ toggleSidebar }) => {
  return (
    <header className="app-header">
      <div className="header-left">
        <button 
          className="sidebar-toggle" 
          onClick={toggleSidebar}
          aria-label="Toggle Sidebar"
        >
          <span>≡</span>
        </button>
        <div className="logo">
          <Link to="/">
            <span className="logo-text">JWTKit</span>
          </Link>
        </div>
      </div>
      
      <div className="header-right">
        <a 
          href="https://github.com/eshanized/JWTKit" 
          target="_blank" 
          rel="noopener noreferrer"
          className="github-link"
        >
          GitHub
        </a>
      </div>
    </header>
  );
};

export default Header;