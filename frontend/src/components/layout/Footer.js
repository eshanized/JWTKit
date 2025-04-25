import React from 'react';
import './layout.css';

const Footer = () => {
  const currentYear = new Date().getFullYear();
  
  return (
    <footer className="app-footer">
      <div className="footer-container">
        <div className="footer-left">
          <p className="copyright">
            &copy; {currentYear} JWTKit. All rights reserved.
          </p>
        </div>
        
        <div className="footer-center">
          <nav className="footer-nav">
            <a href="/about" className="footer-link">About</a>
            <a href="/privacy" className="footer-link">Privacy</a>
            <a href="/terms" className="footer-link">Terms</a>
            <a href="/contact" className="footer-link">Contact</a>
          </nav>
        </div>
        
        <div className="footer-right">
          <div className="social-links">
            <a href="https://github.com/eshanized/JWTKit" target="_blank" rel="noopener noreferrer" className="social-link">
              <i className="fab fa-github"></i>
            </a>
            <a href="https://twitter.com" target="_blank" rel="noopener noreferrer" className="social-link">
              <i className="fab fa-twitter"></i>
            </a>
            <a href="https://linkedin.com" target="_blank" rel="noopener noreferrer" className="social-link">
              <i className="fab fa-linkedin"></i>
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer; 