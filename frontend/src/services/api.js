import axios from 'axios';

// Create an axios instance with default config
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add a request interceptor for auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Add a response interceptor to handle errors and token expiration
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Only handle 401 errors when user thought they were logged in
    if (error.response?.status === 401 && localStorage.getItem('token')) {
      // Clear token and notify app of logout
      localStorage.removeItem('token');
      
      // Could dispatch to redux or notify context
      window.dispatchEvent(new CustomEvent('auth:logout', {
        detail: { reason: 'session-expired' }
      }));
    }
    
    return Promise.reject(error);
  }
);

// Helper to set auth token for all future requests
export const setAuthToken = (token) => {
  if (token) {
    api.defaults.headers.common.Authorization = `Bearer ${token}`;
  } else {
    delete api.defaults.headers.common.Authorization;
  }
};

// Get current user info - returns guest user if not logged in
export const getCurrentUser = () => {
  const userData = localStorage.getItem('user');
  if (userData) {
    return JSON.parse(userData);
  }
  
  // Return a guest user when not authenticated
  return {
    username: 'guest',
    role: 'guest',
    isGuest: true
  };
};

// Enhanced API service with guest user support
export const apiService = {
  // Auth endpoints
  auth: {
    login: (credentials) => api.post('/api/auth/login', credentials),
    register: (userData) => api.post('/api/auth/register', userData),
    getUser: () => {
      const token = localStorage.getItem('token');
      if (token) {
        return api.get('/api/auth/user');
      }
      // Return mock response for guest user
      return Promise.resolve({
        data: {
          username: 'guest',
          role: 'guest',
          isGuest: true
        }
      });
    },
    updateProfile: (userData) => api.put('/api/auth/profile', userData),
    changePassword: (passwordData) => api.post('/api/auth/change-password', passwordData),
  },
  
  // Token manipulation endpoints
  tokens: {
    decode: (token) => api.post('/api/token/decode', { token }),
    verify: (token, key, algorithm) => api.post('/api/token/verify', { token, key, algorithm }),
    modify: (token, newPayload, key, algorithm) => 
      api.post('/api/token/modify', { token, new_payload: newPayload, key, algorithm }),
    create: (payload, key, algorithm, headers) => 
      api.post('/api/token/create', { payload, key, algorithm, headers }),
    getSamples: () => api.get('/api/token/generate-samples'),
    saveToken: (tokenData) => api.post('/api/saved-tokens', tokenData),
    getTokens: () => api.get('/api/saved-tokens'),
    deleteToken: (id) => api.delete(`/api/saved-tokens/${id}`),
  },
  
  // Vulnerability scanning endpoints
  vulnerabilities: {
    scan: (token) => api.post('/api/vulnerabilities/scan', { token }),
    advancedScan: (token) => api.post('/api/vulnerabilities/advanced-scan', { token }),
    attackVectors: (token) => api.post('/api/vulnerabilities/attack-vectors', { token }),
    recommendations: (token) => api.post('/api/vulnerabilities/recommendations', { token }),
    getReports: () => api.get('/api/vulnerability-reports'),
    saveReport: (reportData) => api.post('/api/vulnerability-reports', reportData),
  },
  
  // Attack simulation endpoints
  attacks: {
    algorithmConfusion: (token, publicKey) => 
      api.post('/api/attacks/algorithm-confusion', { token, public_key: publicKey }),
    bruteForce: (token, wordlist) => 
      api.post('/api/attacks/brute-force', { token, wordlist }),
    tokenFuzzing: (token, fuzzingOptions) => 
      api.post('/api/attacks/fuzzing', { token, options: fuzzingOptions }),
    keyInjection: (token, injectionData) => 
      api.post('/api/attacks/key-injection', { token, ...injectionData }),
    runSimulation: (config) => 
      api.post('/api/attacks/simulation', config),
  },
  
  // Key management endpoints
  keys: {
    getKeys: () => api.get('/api/keys'),
    createKey: (keyData) => api.post('/api/keys', keyData),
    generateRsa: (keySize) => api.post('/api/keys/generate-rsa', { key_size: keySize }),
    generateEc: (curve) => api.post('/api/keys/generate-ec', { curve }),
    generateHmac: (keySize) => api.post('/api/keys/generate-hmac', { key_size: keySize }),
    deleteKey: (id) => api.delete(`/api/keys/${id}`),
  },
  
  // Utility endpoints
  utils: {
    getAuditLogs: (params) => api.get('/api/audit', { params }),
    getSettings: () => api.get('/api/settings'),
    updateSettings: (settings) => api.post('/api/settings', settings),
    generateReport: (config) => api.post('/api/reports/generate', config),
    getMetrics: () => api.get('/api/metrics'),
  }
};

export default api; 