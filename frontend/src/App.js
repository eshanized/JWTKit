import React, { useState, useEffect } from 'react';
import { Container, Nav, Navbar, Row, Col, Button, Badge } from 'react-bootstrap';
import './App.css';
import JwtDecoder from './components/JwtDecoder';
import VulnerabilityScanner from './components/VulnerabilityScanner';
import SignatureVerifier from './components/SignatureVerifier';
import AlgorithmConfusion from './components/AlgorithmConfusion';
import PayloadEditor from './components/PayloadEditor';
import TokenTester from './components/TokenTester';
import BruteForceEngine from './components/BruteForceEngine';
import AttackSimulator from './components/AttackSimulator';

// Add Font Awesome CSS (add this to your public/index.html)
// <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />

function App() {
  const [activeTab, setActiveTab] = useState('decoder');
  const [jwtToken, setJwtToken] = useState('');
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [showTypingEffect, setShowTypingEffect] = useState(true);

  useEffect(() => {
    // Reset typing effect when tab changes
    setShowTypingEffect(false);
    setTimeout(() => setShowTypingEffect(true), 100);
  }, [activeTab]);

  const handleTokenChange = (token) => {
    setJwtToken(token);
  };

  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
    // Additional logic for implementing dark mode would go here
  };

  const navItems = [
    { id: 'decoder', label: 'JWT Decoder', icon: 'fa-solid fa-unlock-keyhole', notification: false },
    { id: 'vulnerabilities', label: 'Vulnerability Scanner', icon: 'fa-solid fa-shield-virus', notification: false },
    { id: 'verifier', label: 'Signature Verifier', icon: 'fa-solid fa-signature', notification: false },
    { id: 'confusion', label: 'Algorithm Confusion', icon: 'fa-solid fa-code-compare', notification: false },
    { id: 'editor', label: 'Payload Editor', icon: 'fa-solid fa-pen-to-square', notification: false },
    { id: 'tester', label: 'Token Tester', icon: 'fa-solid fa-vial', notification: false },
    { id: 'bruteforce', label: 'Brute Force', icon: 'fa-solid fa-hammer', notification: false },
    { id: 'simulator', label: 'Attack Simulator', icon: 'fa-solid fa-bug', notification: true }
  ];

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'decoder':
        return <JwtDecoder token={jwtToken} onTokenChange={handleTokenChange} />;
      case 'vulnerabilities':
        return <VulnerabilityScanner token={jwtToken} />;
      case 'verifier':
        return <SignatureVerifier token={jwtToken} />;
      case 'confusion':
        return <AlgorithmConfusion token={jwtToken} onTokenChange={handleTokenChange} />;
      case 'editor':
        return <PayloadEditor token={jwtToken} onTokenChange={handleTokenChange} />;
      case 'tester':
        return <TokenTester token={jwtToken} />;
      case 'bruteforce':
        return <BruteForceEngine token={jwtToken} />;
      case 'simulator':
        return <AttackSimulator token={jwtToken} />;
      default:
        return <JwtDecoder token={jwtToken} onTokenChange={handleTokenChange} />;
    }
  };

  // Render loading animation
  const renderLoadingDots = () => (
    <div className="loading-animation">
      <span className="loading-dot"></span>
      <span className="loading-dot"></span>
      <span className="loading-dot"></span>
    </div>
  );

  return (
    <div className={`App ${isDarkMode ? 'dark-mode' : ''}`}>
      <Navbar expand="lg" className="navbar-custom">
        <Container>
          <Navbar.Brand href="#home" className="d-flex align-items-center">
            <i className="fa-solid fa-key brand-icon me-2"></i>
            <span>JWTKit</span>
            <span className="text-muted ms-2 small d-none d-md-inline">JWT Analyzer & Attacker</span>
          </Navbar.Brand>
          <div className="d-flex align-items-center ms-auto me-2">
            <div 
              className={`dark-mode-toggle ${isDarkMode ? 'active' : ''}`} 
              onClick={toggleDarkMode}
              title="Toggle dark mode"
            ></div>
          </div>
          <Navbar.Toggle aria-controls="basic-navbar-nav" />
          <Navbar.Collapse id="basic-navbar-nav">
            <Nav className="ms-auto">
              {navItems.map(item => (
                <Nav.Link 
                  key={item.id}
                  href={`#${item.id}`} 
                  active={activeTab === item.id} 
                  onClick={() => setActiveTab(item.id)}
                  className={`nav-item-animated ${item.notification ? 'notification-badge' : ''}`}
                >
                  <i className={`${item.icon} me-1`}></i>
                  <span className="d-none d-lg-inline">{item.label}</span>
                </Nav.Link>
              ))}
            </Nav>
          </Navbar.Collapse>
        </Container>
      </Navbar>

      <Container className="main-container">
        <Row className="mb-4">
          <Col>
            <div className="page-header animate-slide-up">
              <h2 className="section-heading">
                <i className={navItems.find(item => item.id === activeTab)?.icon}></i>
                {showTypingEffect ? (
                  <span className="typing-effect ms-2">
                    {navItems.find(item => item.id === activeTab)?.label}
                  </span>
                ) : renderLoadingDots()}
              </h2>
            </div>
          </Col>
        </Row>
        <div className="content-container glass-panel p-4 animate-fade-in">
          {jwtToken && (
            <div className="token-summary mb-4">
              <Row className="align-items-center">
                <Col md={8}>
                  <div className="token-display">
                    <code className="text-break">{jwtToken.length > 60 ? `${jwtToken.substring(0, 40)}...${jwtToken.substring(jwtToken.length - 20)}` : jwtToken}</code>
                    <Button size="sm" variant="light" className="copy-btn">
                      <i className="fa-regular fa-copy"></i>
                    </Button>
                  </div>
                </Col>
                <Col md={4} className="text-end">
                  <Badge bg="primary" className="me-2">
                    <i className="fa-solid fa-code me-1"></i> JWT
                  </Badge>
                  {jwtToken.includes('.') && (
                    <Badge bg="success">
                      <i className="fa-solid fa-check-circle me-1"></i> Valid Format
                    </Badge>
                  )}
                </Col>
              </Row>
            </div>
          )}
          {renderActiveTab()}
        </div>
      </Container>
      
      <footer className="text-center p-4">
        <Container>
          <Row>
            <Col md={8} className="mx-auto">
              <p className="mb-0 small">
                <i className="fa-solid fa-shield-halved me-2"></i>
                JWTKit is for educational and authorized penetration testing only. 
                Unauthorized use against systems without permission is illegal and unethical.
              </p>
            </Col>
          </Row>
        </Container>
      </footer>
    </div>
  );
}

export default App;