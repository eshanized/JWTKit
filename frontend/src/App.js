import React, { useState, useEffect, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import axios from 'axios';
import './App.css';
import './AppLayout.css';

// Components
import Header from './components/layout/Header';
import Sidebar from './components/layout/Sidebar';
import Footer from './components/layout/Footer';
import Dashboard from './components/Dashboard';
import JwtDecoder from './components/JwtDecoder';
import TokenFuzzer from './components/TokenFuzzer';
import AttackAnalytics from './components/AttackAnalytics';
import SecurityPatternDetector from './components/SecurityPatternDetector';
import AuditLog from './components/AuditLog';
import TokenComparison from './components/TokenComparison';
import TokenTester from './components/TokenTester';
import ValidationFeedback from './components/ValidationFeedback';
import AttackSimulator from './components/AttackSimulator';
import SignatureVerifier from './components/SignatureVerifier';
import PayloadEditor from './components/PayloadEditor';
import BruteForceEngine from './components/BruteForceEngine';
import AlgorithmConfusion from './components/AlgorithmConfusion';
import VulnerabilityScanner from './components/VulnerabilityScanner';
import Login from './components/auth/Login';
import Register from './components/auth/Register';
import Profile from './components/auth/Profile';
import TokenHistory from './components/TokenHistory';
import SecurityRecommendations from './components/SecurityRecommendations';
import AttackVectorAnalysis from './components/AttackVectorAnalysis';
import KeyManager from './components/KeyManager';
import Settings from './components/Settings';
import ReportGenerator from './components/ReportGenerator';
import NotFound from './components/layout/NotFound';
// import Toast from './components/Toast';
import ToastContainer from './components/ToastContainer';
import ErrorBoundary from './components/ErrorBoundary';

// Context
import AuthContext, { AuthProvider } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import { ThemeProvider } from './context/ThemeContext';

// Services
import { setAuthToken } from './services/api';

function App() {
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');
  const [dark] = useState(localStorage.getItem('darkMode') === 'true');
  const [loggedIn, setLoggedIn] = useContext(AuthContext);
  const [auditLogs, setAuditLogs] = useState([]);
  
  // Initialize auth state
  useEffect(() => {
    console.log('App useEffect: checking token and auth status');
    const token = localStorage.getItem('token');
    
    if (token) {
      setAuthToken(token);
      checkAuthStatus();
    } else {
      console.log('No token found, setting isLoading to false');
      setIsLoading(false);
    }
    
    // Apply theme
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);
  
  useEffect(() => {
    // Check if user is logged in on initial load
    const token = localStorage.getItem('jwt');
    if (token) {
      setLoggedIn(true);
    }
    
    // Set dark mode from localStorage
    document.body.className = dark ? 'dark-mode' : '';
    localStorage.setItem('darkMode', dark);
  }, [dark, setLoggedIn]);

  useEffect(() => {
    // Fetch audit logs when user is logged in
    if (loggedIn) {
      fetchAuditLogs();
    }
  }, [loggedIn]);
  
  // Verify token and load user data
  const checkAuthStatus = async () => {
    try {
      console.log('Checking auth status...');
      const response = await axios.get('/api/auth/user');
      console.log('Auth status response:', response);
      setUser(response.data);
      setIsAuthenticated(true);
    } catch (error) {
      console.error('Auth verification failed:', error);
      localStorage.removeItem('token');
      setAuthToken(null);
    } finally {
      console.log('Setting isLoading to false');
      setIsLoading(false);
    }
  };
  
  // Handle login
  const handleLogin = (token, userData) => {
    localStorage.setItem('token', token);
    setAuthToken(token);
    setUser(userData);
    setIsAuthenticated(true);
  };
  
  // Handle logout
  const handleLogout = () => {
    localStorage.removeItem('token');
    setAuthToken(null);
    setUser(null);
    setIsAuthenticated(false);
  };
  
  // Toggle sidebar
  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };
  
  // Toggle theme
  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    localStorage.setItem('theme', newTheme);
  };

  const fetchAuditLogs = async () => {
    try {
      const response = await fetch('http://localhost:8000/audit/logs');
      const data = await response.json();
      setAuditLogs(data);
    } catch (error) {
      console.error('Error fetching audit logs:', error);
    }
  };
  
  if (isLoading) {
    console.log('App is loading...');
    return (
      <div className="app-loading">
        <div className="spinner"></div>
        <p>Loading JWTKit...</p>
      </div>
    );
  }
  
  return (
    <ErrorBoundary>
      <ThemeProvider value={{ theme, toggleTheme }}>
        <AuthProvider value={{ isAuthenticated, user, login: handleLogin, logout: handleLogout }}>
          <ToastProvider>
            <Router>
              <div className={`app ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
                <Header toggleSidebar={toggleSidebar} />
                <Sidebar isOpen={sidebarOpen} />
                <main className="main-content">
                  <Routes>
                    {/* All routes are now public */}
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/login" element={<Login />} />
                    <Route path="/register" element={<Register />} />
                    <Route path="/decode" element={<JwtDecoder />} />
                    <Route path="/verify" element={<SignatureVerifier />} />
                    <Route path="/vulnerabilities" element={<VulnerabilityScanner />} />
                    <Route path="/profile" element={<Profile />} />
                    <Route path="/modify" element={<PayloadEditor />} />
                    <Route path="/attacks/algorithm-confusion" element={<AlgorithmConfusion />} />
                    <Route path="/attacks/brute-force" element={<BruteForceEngine />} />
                    <Route path="/tokens/test" element={<TokenTester />} />
                    <Route path="/tokens/fuzzer" element={<TokenFuzzer />} />
                    <Route path="/tokens/history" element={<TokenHistory />} />
                    <Route path="/tokens/compare" element={<TokenComparison />} />
                    <Route path="/analytics" element={<AttackAnalytics />} />
                    <Route path="/attack-vectors" element={<AttackVectorAnalysis />} />
                    <Route path="/security-patterns" element={<SecurityPatternDetector logs={auditLogs} />} />
                    <Route path="/audit" element={<AuditLog />} />
                    <Route path="/attack-simulator" element={<AttackSimulator />} />
                    <Route path="/validation" element={<ValidationFeedback />} />
                    <Route path="/recommendations" element={<SecurityRecommendations />} />
                    <Route path="/keys" element={<KeyManager />} />
                    <Route path="/settings" element={<Settings />} />
                    <Route path="/reports" element={<ReportGenerator />} />
                    
                    {/* Fallback route */}
                    <Route path="*" element={<NotFound />} />
                  </Routes>
                </main>
                <Footer />
                <ToastContainer />
              </div>
            </Router>
          </ToastProvider>
        </AuthProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
