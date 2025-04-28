import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';

// Layout Components
import Header from './components/layout/Header';
import Sidebar from './components/layout/Sidebar';
import Footer from './components/layout/Footer';

// Page Components
import Dashboard from './components/Dashboard';
import JwtDecoder from './components/tools/JwtDecoder';
import SignatureVerifier from './components/tools/SignatureVerifier';
import VulnerabilityScanner from './components/tools/VulnerabilityScanner';
import PayloadEditor from './components/tools/PayloadEditor';
import NotFound from './components/layout/NotFound';

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  
  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };
  
  return (
    <Router>
      <div className="app-wrapper">
        <Header toggleSidebar={toggleSidebar} />
        <div className="content-wrapper">
          <Sidebar isOpen={sidebarOpen} />
          <main className={`main-content ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/decode" element={<JwtDecoder />} />
              <Route path="/verify" element={<SignatureVerifier />} />
              <Route path="/scan" element={<VulnerabilityScanner />} />
              <Route path="/edit" element={<PayloadEditor />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
        </div>
        <Footer />
      </div>
    </Router>
  );
}

export default App; 