import React from 'react';
import { Link } from 'react-router-dom';
import './Dashboard.css';

const Dashboard = () => {
  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Welcome to JWTKit</h1>
        <p>A comprehensive toolkit for JWT analysis, testing, and debugging</p>
      </div>
      
      <div className="dashboard-cards">
        <div className="dashboard-card">
          <div className="card-icon">🔍</div>
          <h2>Decode JWT</h2>
          <p>Decode and inspect JWT tokens without sending sensitive data to the server.</p>
          <Link to="/decode" className="card-link">
            Decode a Token
          </Link>
        </div>
        
        <div className="dashboard-card">
          <div className="card-icon">✓</div>
          <h2>Verify Signature</h2>
          <p>Verify JWT signatures using various algorithms and keys.</p>
          <Link to="/verify" className="card-link">
            Verify Signature
          </Link>
        </div>
        
        <div className="dashboard-card">
          <div className="card-icon">🔒</div>
          <h2>Scan Vulnerabilities</h2>
          <p>Analyze tokens for common security issues and vulnerabilities.</p>
          <Link to="/scan" className="card-link">
            Scan Token
          </Link>
        </div>
        
        <div className="dashboard-card">
          <div className="card-icon">✏️</div>
          <h2>Edit Payload</h2>
          <p>Modify JWT payload and create new tokens.</p>
          <Link to="/edit" className="card-link">
            Edit Token
          </Link>
        </div>
      </div>
      
      <div className="dashboard-info">
        <h3>About JWTKit</h3>
        <p>
          JWTKit is an open-source tool for developers and security professionals
          to analyze, test, and debug JSON Web Tokens (JWTs). All JWT operations
          are performed locally in your browser for maximum security.
        </p>
      </div>
    </div>
  );
};

export default Dashboard; 