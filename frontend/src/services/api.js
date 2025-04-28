import axios from 'axios';

// Create axios instance with default config
const api = axios.create({
  baseURL: 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Intercept requests to add auth token when available
api.interceptors.request.use(
  config => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  error => {
    return Promise.reject(error);
  }
);

// Intercept responses to handle common errors
api.interceptors.response.use(
  response => response,
  error => {
    if (error.response) {
      // Handle specific HTTP error codes
      switch (error.response.status) {
        case 401:
          // Unauthorized - clear local storage and redirect to login
          localStorage.removeItem('token');
          // window.location.href = '/login';
          break;
        case 403:
          console.error('Forbidden access');
          break;
        case 500:
          console.error('Server error');
          break;
        default:
          console.error('Request failed:', error.response.data);
      }
    } else if (error.request) {
      // Request made but no response received
      console.error('No response received:', error.request);
    } else {
      // Something else caused the error
      console.error('Error setting up the request:', error.message);
    }
    return Promise.reject(error);
  }
);

// Helper function to set auth token
export const setAuthToken = token => {
  if (token) {
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    delete api.defaults.headers.common['Authorization'];
  }
};

// Api methods
export const decodeToken = (token) => api.post('/decode', { token });
export const verifyToken = (token, secret, algorithm = 'HS256') => 
  api.post('/verify', { token, secret, algorithm });
export const scanVulnerabilities = (token) => api.post('/vulnerabilities', { token });
export const modifyToken = (token, newPayload, secret, algorithm = 'HS256') => 
  api.post('/modify', { token, new_payload: newPayload, secret, algorithm });

export default api; 