import React, { useState } from 'react';
import { Container, Nav, Navbar } from 'react-bootstrap';
import './App.css';
import JwtDecoder from './components/JwtDecoder';
import VulnerabilityScanner from './components/VulnerabilityScanner';
import SignatureVerifier from './components/SignatureVerifier';
import AlgorithmConfusion from './components/AlgorithmConfusion';
import PayloadEditor from './components/PayloadEditor';
import TokenTester from './components/TokenTester';
import BruteForceEngine from './components/BruteForceEngine';
import AttackSimulator from './components/AttackSimulator';

function App() {
  const [activeTab, setActiveTab] = useState('decoder');
  const [jwtToken, setJwtToken] = useState('');

  const handleTokenChange = (token) => {
    setJwtToken(token);
  };

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

  return (
    <div className="App">
      <Navbar bg="dark" variant="dark" expand="lg">
        <Container>
          <Navbar.Brand href="#home">
            🔐 JWTKit - JWT Analyzer & Attacker
          </Navbar.Brand>
          <Navbar.Toggle aria-controls="basic-navbar-nav" />
          <Navbar.Collapse id="basic-navbar-nav">
            <Nav className="me-auto">
              <Nav.Link 
                href="#decoder" 
                active={activeTab === 'decoder'} 
                onClick={() => setActiveTab('decoder')}
              >
                JWT Decoder
              </Nav.Link>
              <Nav.Link 
                href="#vulnerabilities" 
                active={activeTab === 'vulnerabilities'} 
                onClick={() => setActiveTab('vulnerabilities')}
              >
                Vulnerability Scanner
              </Nav.Link>
              <Nav.Link 
                href="#verifier" 
                active={activeTab === 'verifier'} 
                onClick={() => setActiveTab('verifier')}
              >
                Signature Verifier
              </Nav.Link>
              <Nav.Link 
                href="#confusion" 
                active={activeTab === 'confusion'} 
                onClick={() => setActiveTab('confusion')}
              >
                Algorithm Confusion
              </Nav.Link>
              <Nav.Link 
                href="#editor" 
                active={activeTab === 'editor'} 
                onClick={() => setActiveTab('editor')}
              >
                Payload Editor
              </Nav.Link>
              <Nav.Link 
                href="#tester" 
                active={activeTab === 'tester'} 
                onClick={() => setActiveTab('tester')}
              >
                Token Tester
              </Nav.Link>
              <Nav.Link 
                href="#bruteforce" 
                active={activeTab === 'bruteforce'} 
                onClick={() => setActiveTab('bruteforce')}
              >
                Brute Force
              </Nav.Link>
              <Nav.Link 
                href="#simulator" 
                active={activeTab === 'simulator'} 
                onClick={() => setActiveTab('simulator')}
              >
                Attack Simulator
              </Nav.Link>
            </Nav>
          </Navbar.Collapse>
        </Container>
      </Navbar>

      <Container className="mt-4">
        {renderActiveTab()}
      </Container>
      
      <footer className="mt-5 p-3 text-center bg-light">
        <small>
          JWTKit is for educational and authorized penetration testing only. 
          Unauthorized use against systems without permission is illegal and unethical.
        </small>
      </footer>
    </div>
  );
}

export default App;