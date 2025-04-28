#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}   Starting JWTKit - JWT Analysis Tool   ${NC}"
echo -e "${BLUE}=========================================${NC}"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed. Please install Python 3.${NC}"
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}Node.js is not installed. Please install Node.js.${NC}"
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo -e "${RED}npm is not installed. Please install npm.${NC}"
    exit 1
fi

# Create Python virtual environment if it doesn't exist
if [ ! -d "flask_env" ]; then
    echo -e "${BLUE}Setting up Python virtual environment...${NC}"
    python3 -m venv flask_env
fi

# Activate virtual environment and install dependencies
echo -e "${BLUE}Installing backend dependencies...${NC}"
source flask_env/bin/activate
pip install werkzeug==2.2.3 flask==2.2.3 flask-cors==3.0.10 pyjwt==2.6.0 python-multipart==0.0.6 cryptography==40.0.2 requests==2.30.0 sqlalchemy==1.4.40 passlib==1.7.4 python-dotenv==1.0.0 flask-jwt-extended==4.4.4 flask-limiter==3.3.1

# Start backend server in the background
echo -e "${GREEN}Starting backend server...${NC}"
python app.py &
BACKEND_PID=$!

# Install frontend dependencies
echo -e "${BLUE}Installing frontend dependencies...${NC}"
cd frontend

# Check if frontend components directory structure exists
if [ ! -d "src/components" ]; then
    echo -e "${YELLOW}Creating missing component directory structure...${NC}"
    mkdir -p src/components/layout
    mkdir -p src/components/auth
    mkdir -p src/context
fi

# Create missing components
echo -e "${YELLOW}Creating missing component files...${NC}"
if [ ! -f "src/components/Dashboard.js" ]; then
    echo -e "${YELLOW}Creating Dashboard component...${NC}"
    cat > src/components/Dashboard.js << 'EOF'
import React from 'react';

const Dashboard = () => {
  return (
    <div className="dashboard">
      <h1>JWTKit Dashboard</h1>
      <p>Welcome to JWTKit, a comprehensive JWT analysis and testing tool.</p>
      <div className="dashboard-cards">
        <div className="dashboard-card">
          <h3>Decode Tokens</h3>
          <p>Decode and inspect JWT tokens</p>
        </div>
        <div className="dashboard-card">
          <h3>Verify Signatures</h3>
          <p>Verify JWT signatures with different algorithms</p>
        </div>
        <div className="dashboard-card">
          <h3>Scan Vulnerabilities</h3>
          <p>Scan JWTs for common vulnerabilities</p>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
EOF
fi

# Create other basic components needed
if [ ! -f "src/components/layout/Header.js" ]; then
    echo -e "${YELLOW}Creating Header component...${NC}"
    cat > src/components/layout/Header.js << 'EOF'
import React from 'react';

const Header = ({ toggleSidebar }) => {
  return (
    <header className="app-header">
      <div className="header-left">
        <button className="sidebar-toggle" onClick={toggleSidebar}>
          ≡
        </button>
        <div className="logo">JWTKit</div>
      </div>
      <div className="header-right">
        <span className="user-info">JWT Analysis Tool</span>
      </div>
    </header>
  );
};

export default Header;
EOF
fi

if [ ! -f "src/components/layout/Sidebar.js" ]; then
    echo -e "${YELLOW}Creating Sidebar component...${NC}"
    cat > src/components/layout/Sidebar.js << 'EOF'
import React from 'react';
import { Link } from 'react-router-dom';

const Sidebar = ({ isOpen }) => {
  return (
    <aside className={`sidebar ${isOpen ? 'open' : 'closed'}`}>
      <nav className="sidebar-nav">
        <ul>
          <li><Link to="/">Dashboard</Link></li>
          <li><Link to="/decode">Decode</Link></li>
          <li><Link to="/verify">Verify</Link></li>
          <li><Link to="/vulnerabilities">Scan</Link></li>
        </ul>
      </nav>
    </aside>
  );
};

export default Sidebar;
EOF
fi

if [ ! -f "src/components/layout/Footer.js" ]; then
    echo -e "${YELLOW}Creating Footer component...${NC}"
    cat > src/components/layout/Footer.js << 'EOF'
import React from 'react';

const Footer = () => {
  return (
    <footer className="app-footer">
      <p>JWTKit &copy; {new Date().getFullYear()}</p>
    </footer>
  );
};

export default Footer;
EOF
fi

if [ ! -f "src/components/layout/NotFound.js" ]; then
    echo -e "${YELLOW}Creating NotFound component...${NC}"
    cat > src/components/layout/NotFound.js << 'EOF'
import React from 'react';

const NotFound = () => {
  return (
    <div className="not-found">
      <h1>404 - Page Not Found</h1>
      <p>The page you are looking for does not exist.</p>
    </div>
  );
};

export default NotFound;
EOF
fi

# Create basic context providers
if [ ! -f "src/context/ThemeContext.js" ]; then
    echo -e "${YELLOW}Creating ThemeContext...${NC}"
    cat > src/context/ThemeContext.js << 'EOF'
import React, { createContext, useState } from 'react';

const ThemeContext = createContext();

export const ThemeProvider = ({ children, value }) => {
  const [theme, setTheme] = useState(value?.theme || 'light');
  
  const toggleTheme = () => {
    setTheme(theme === 'light' ? 'dark' : 'light');
  };
  
  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

export default ThemeContext;
EOF
fi

if [ ! -f "src/context/AuthContext.js" ]; then
    echo -e "${YELLOW}Creating AuthContext...${NC}"
    cat > src/context/AuthContext.js << 'EOF'
import React, { createContext, useState } from 'react';

const AuthContext = createContext([false, () => {}]);

export const AuthProvider = ({ children, value }) => {
  const [loggedIn, setLoggedIn] = useState(value?.isAuthenticated || false);
  
  return (
    <AuthContext.Provider value={[loggedIn, setLoggedIn]}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;
EOF
fi

if [ ! -f "src/context/ToastContext.js" ]; then
    echo -e "${YELLOW}Creating ToastContext...${NC}"
    cat > src/context/ToastContext.js << 'EOF'
import React, { createContext, useState } from 'react';

const ToastContext = createContext();

export const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);
  
  const addToast = (message, type = 'info') => {
    const id = Date.now();
    setToasts([...toasts, { id, message, type }]);
    
    setTimeout(() => {
      removeToast(id);
    }, 5000);
  };
  
  const removeToast = (id) => {
    setToasts(toasts.filter(toast => toast.id !== id));
  };
  
  return (
    <ToastContext.Provider value={{ toasts, addToast, removeToast }}>
      {children}
    </ToastContext.Provider>
  );
};

export default ToastContext;
EOF
fi

# Create other required components
if [ ! -f "src/components/JwtDecoder.js" ]; then
    echo -e "${YELLOW}Creating JwtDecoder component...${NC}"
    cat > src/components/JwtDecoder.js << 'EOF'
import React, { useState } from 'react';

const JwtDecoder = () => {
  const [token, setToken] = useState('');
  const [decoded, setDecoded] = useState(null);
  
  const handleTokenChange = (e) => {
    setToken(e.target.value);
  };
  
  const decodeToken = () => {
    try {
      // Basic JWT decoding
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }
      
      // Decode header and payload
      const header = JSON.parse(atob(parts[0]));
      const payload = JSON.parse(atob(parts[1]));
      
      setDecoded({ header, payload, signature: parts[2] });
    } catch (error) {
      console.error('Error decoding token:', error);
      setDecoded({ error: error.message });
    }
  };
  
  return (
    <div className="jwt-decoder">
      <h2>JWT Decoder</h2>
      <div className="jwt-input">
        <textarea 
          value={token}
          onChange={handleTokenChange}
          placeholder="Paste your JWT token here..."
          rows={5}
        />
        <button onClick={decodeToken}>Decode</button>
      </div>
      
      {decoded && (
        <div className="jwt-result">
          {decoded.error ? (
            <div className="error">{decoded.error}</div>
          ) : (
            <>
              <div className="jwt-part">
                <h3>Header</h3>
                <pre>{JSON.stringify(decoded.header, null, 2)}</pre>
              </div>
              <div className="jwt-part">
                <h3>Payload</h3>
                <pre>{JSON.stringify(decoded.payload, null, 2)}</pre>
              </div>
              <div className="jwt-part">
                <h3>Signature</h3>
                <pre>{decoded.signature}</pre>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default JwtDecoder;
EOF
fi

if [ ! -f "src/components/VulnerabilityScanner.js" ]; then
    echo -e "${YELLOW}Creating VulnerabilityScanner component...${NC}"
    cat > src/components/VulnerabilityScanner.js << 'EOF'
import React, { useState } from 'react';

const VulnerabilityScanner = () => {
  const [token, setToken] = useState('');
  const [results, setResults] = useState(null);
  
  const handleTokenChange = (e) => {
    setToken(e.target.value);
  };
  
  const scanToken = async () => {
    try {
      const response = await fetch('http://localhost:8000/vulnerabilities', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token }),
      });
      
      const data = await response.json();
      setResults(data);
    } catch (error) {
      console.error('Error scanning token:', error);
      setResults({ error: error.message });
    }
  };
  
  return (
    <div className="vulnerability-scanner">
      <h2>Vulnerability Scanner</h2>
      <div className="scanner-input">
        <textarea 
          value={token}
          onChange={handleTokenChange}
          placeholder="Paste your JWT token here..."
          rows={5}
        />
        <button onClick={scanToken}>Scan for Vulnerabilities</button>
      </div>
      
      {results && (
        <div className="scanner-results">
          {results.error ? (
            <div className="error">{results.error}</div>
          ) : (
            <>
              <h3>Scan Results</h3>
              {results.vulnerabilities && results.vulnerabilities.length > 0 ? (
                <div className="vulnerabilities-list">
                  {results.vulnerabilities.map((vuln, index) => (
                    <div key={index} className={`vulnerability-item ${vuln.severity}`}>
                      <h4>{vuln.issue}</h4>
                      <p>{vuln.description}</p>
                      <span className="severity-badge">{vuln.severity}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p>No vulnerabilities found</p>
              )}
              
              {results.recommendations && (
                <div className="recommendations">
                  <h3>Recommendations</h3>
                  <ul>
                    {results.recommendations.map((rec, index) => (
                      <li key={index}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default VulnerabilityScanner;
EOF
fi

if [ ! -f "src/components/SignatureVerifier.js" ]; then
    echo -e "${YELLOW}Creating SignatureVerifier component...${NC}"
    cat > src/components/SignatureVerifier.js << 'EOF'
import React, { useState } from 'react';

const SignatureVerifier = () => {
  const [token, setToken] = useState('');
  const [secret, setSecret] = useState('');
  const [algorithm, setAlgorithm] = useState('HS256');
  const [result, setResult] = useState(null);
  
  const handleTokenChange = (e) => {
    setToken(e.target.value);
  };
  
  const handleSecretChange = (e) => {
    setSecret(e.target.value);
  };
  
  const handleAlgorithmChange = (e) => {
    setAlgorithm(e.target.value);
  };
  
  const verifySignature = async () => {
    try {
      const response = await fetch('http://localhost:8000/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token, secret, algorithm }),
      });
      
      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error('Error verifying token:', error);
      setResult({ valid: false, error: error.message });
    }
  };
  
  return (
    <div className="signature-verifier">
      <h2>JWT Signature Verifier</h2>
      <div className="verifier-form">
        <div className="form-group">
          <label>JWT Token:</label>
          <textarea 
            value={token}
            onChange={handleTokenChange}
            placeholder="Paste your JWT token here..."
            rows={5}
          />
        </div>
        
        <div className="form-group">
          <label>Secret Key:</label>
          <input 
            type="text" 
            value={secret}
            onChange={handleSecretChange}
            placeholder="Enter your secret key"
          />
        </div>
        
        <div className="form-group">
          <label>Algorithm:</label>
          <select value={algorithm} onChange={handleAlgorithmChange}>
            <option value="HS256">HS256</option>
            <option value="HS384">HS384</option>
            <option value="HS512">HS512</option>
            <option value="RS256">RS256</option>
            <option value="RS384">RS384</option>
            <option value="RS512">RS512</option>
          </select>
        </div>
        
        <button onClick={verifySignature}>Verify Signature</button>
      </div>
      
      {result && (
        <div className={`verification-result ${result.valid ? 'valid' : 'invalid'}`}>
          <h3>Verification Result</h3>
          {result.valid ? (
            <>
              <p className="success">✓ Signature is valid</p>
              {result.payload && (
                <div className="verified-payload">
                  <h4>Payload:</h4>
                  <pre>{JSON.stringify(result.payload, null, 2)}</pre>
                </div>
              )}
            </>
          ) : (
            <p className="error">✗ {result.error || 'Invalid signature'}</p>
          )}
        </div>
      )}
    </div>
  );
};

export default SignatureVerifier;
EOF
fi

# Update package.json to fix version issues
echo -e "${BLUE}Updating package.json to fix version conflicts...${NC}"
if [ -f "package.json" ]; then
    # Create backup of package.json
    cp package.json package.json.bak
    
    # Update React and React-DOM versions
    sed -i 's/"react": "\^19.1.0"/"react": "^18.2.0"/' package.json
    sed -i 's/"react-dom": "\^19.1.0"/"react-dom": "^18.2.0"/' package.json
    
    # Add minimal components
    echo -e "${BLUE}Installing dependencies...${NC}"
    npm install --legacy-peer-deps
    
    # Start frontend server with --force flag to bypass dependency issues
    echo -e "${GREEN}Starting frontend server...${NC}"
    npm start --force &
    FRONTEND_PID=$!
else
    echo -e "${RED}package.json not found! Cannot start frontend server.${NC}"
    kill $BACKEND_PID  # Kill backend server if frontend can't start
    exit 1
fi

cd ..

echo -e "${GREEN}JWTKit is running!${NC}"
echo -e "${BLUE}- Backend:${NC} http://localhost:8000"
echo -e "${BLUE}- Frontend:${NC} http://localhost:3000"
echo -e "${BLUE}- API Docs:${NC} http://localhost:8000/docs"
echo -e "${BLUE}----------------------------------------${NC}"
echo -e "Press Ctrl+C to stop both servers"

# Function to kill processes when script is interrupted
cleanup() {
    echo -e "${RED}Stopping servers...${NC}"
    kill $BACKEND_PID
    kill $FRONTEND_PID
    exit 0
}

# Set trap for SIGINT (Ctrl+C)
trap cleanup SIGINT

# Wait for user to interrupt
wait 