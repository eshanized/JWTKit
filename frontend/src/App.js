import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
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
import AlgorithmConfusion from './components/tools/AlgorithmConfusion';
import BruteForceAttack from './components/tools/BruteForceAttack';
import KeyInjection from './components/tools/KeyInjection';
import JwksSpoofer from './components/tools/JwksSpoofer';
import ExpirationBypass from './components/tools/ExpirationBypass';
import SecurityTester from './components/tools/SecurityTester';
import NotFound from './components/layout/NotFound';

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [darkMode, setDarkMode] = useState(localStorage.getItem('darkMode') === 'true' || false);
  
  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };
  
  const toggleDarkMode = () => {
    const newDarkMode = !darkMode;
    setDarkMode(newDarkMode);
    localStorage.setItem('darkMode', newDarkMode);
  };
  
  const theme = createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: {
        main: '#4A90E2',
      },
      secondary: {
        main: '#f50057',
      },
      background: {
        default: darkMode ? '#121212' : '#f5f5f5',
        paper: darkMode ? '#1e1e1e' : '#ffffff',
      },
    },
    typography: {
      fontFamily: '"Segoe UI", "Roboto", "Helvetica", "Arial", sans-serif',
      h1: {
        fontWeight: 600,
      },
      h2: {
        fontWeight: 600,
      },
      h3: {
        fontWeight: 600,
      },
    },
    components: {
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            textTransform: 'none',
            fontWeight: 600,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            borderRadius: 12,
            boxShadow: '0 4px 20px 0 rgba(0,0,0,0.1)',
          },
        },
      },
    },
  });
  
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <div className="app-wrapper">
          <Header toggleSidebar={toggleSidebar} toggleDarkMode={toggleDarkMode} darkMode={darkMode} />
          <div className="content-wrapper">
            <Sidebar isOpen={sidebarOpen} />
            <main className={`main-content ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/decode" element={<JwtDecoder />} />
                <Route path="/verify" element={<SignatureVerifier />} />
                <Route path="/scan" element={<VulnerabilityScanner />} />
                <Route path="/edit" element={<PayloadEditor />} />
                <Route path="/algorithm-confusion" element={<AlgorithmConfusion />} />
                <Route path="/brute-force" element={<BruteForceAttack />} />
                <Route path="/key-injection" element={<KeyInjection />} />
                <Route path="/jwks-spoofing" element={<JwksSpoofer />} />
                <Route path="/expiration-bypass" element={<ExpirationBypass />} />
                <Route path="/security-tester" element={<SecurityTester />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </main>
          </div>
          <Footer />
        </div>
      </Router>
      <ToastContainer position="bottom-right" theme={darkMode ? 'dark' : 'light'} />
    </ThemeProvider>
  );
}

export default App; 