import React, { useState, useEffect } from 'react';
import axios from 'axios';
import '../Tools.css';

const PayloadEditor = () => {
  const [token, setToken] = useState('');
  const [header, setHeader] = useState('');
  const [payload, setPayload] = useState('');
  const [secret, setSecret] = useState('');
  const [algorithm, setAlgorithm] = useState('HS256');
  const [newToken, setNewToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const algorithms = [
    { id: 'HS256', name: 'HS256', family: 'HMAC' },
    { id: 'HS384', name: 'HS384', family: 'HMAC' },
    { id: 'HS512', name: 'HS512', family: 'HMAC' },
    { id: 'RS256', name: 'RS256', family: 'RSA' },
    { id: 'RS384', name: 'RS384', family: 'RSA' },
    { id: 'RS512', name: 'RS512', family: 'RSA' },
    { id: 'none', name: 'None', family: 'None' }
  ];

  const handleTokenChange = (e) => {
    setToken(e.target.value);
    setError(null);
    setNewToken('');
  };

  const handleHeaderChange = (e) => {
    setHeader(e.target.value);
    setError(null);
    setNewToken('');
  };

  const handlePayloadChange = (e) => {
    setPayload(e.target.value);
    setError(null);
    setNewToken('');
  };

  const handleSecretChange = (e) => {
    setSecret(e.target.value);
    setError(null);
    setNewToken('');
  };

  const selectAlgorithm = (alg) => {
    setAlgorithm(alg);
    setError(null);
    setNewToken('');
  };

  const decodeToken = () => {
    if (!token.trim()) {
      setError('Please enter a JWT token');
      return;
    }

    try {
      // Split the token into parts
      const parts = token.split('.');
      
      if (parts.length !== 3) {
        setError('Invalid JWT format. A JWT should have 3 parts separated by dots.');
        return;
      }

      // Base64 URL decode the header and payload
      const decodeBase64 = (str) => {
        // Replace URL-safe characters and add padding if needed
        const input = str
          .replace(/-/g, '+')
          .replace(/_/g, '/');
        
        const pad = input.length % 4;
        if (pad) {
          if (pad === 1) {
            throw new Error('Invalid base64 string');
          }
          const padding = '=='.substring(0, 4 - pad);
          return atob(input + padding);
        }
        
        return atob(input);
      };

      try {
        const decodedHeader = JSON.parse(decodeBase64(parts[0]));
        const decodedPayload = JSON.parse(decodeBase64(parts[1]));
        
        setHeader(JSON.stringify(decodedHeader, null, 2));
        setPayload(JSON.stringify(decodedPayload, null, 2));
        
        // Set the algorithm from the header if it exists
        if (decodedHeader.alg) {
          setAlgorithm(decodedHeader.alg);
        }
        
        setError(null);
      } catch (e) {
        setError('Error parsing JWT: ' + e.message);
      }
    } catch (e) {
      setError('Error decoding JWT: ' + e.message);
    }
  };

  const generateToken = async () => {
    if (!header.trim() || !payload.trim()) {
      setError('Header and payload are required');
      return;
    }

    if (algorithm !== 'none' && !secret.trim()) {
      setError('Secret key is required for this algorithm');
      return;
    }

    let headerObj, payloadObj;

    try {
      headerObj = JSON.parse(header);
      payloadObj = JSON.parse(payload);
    } catch (e) {
      setError('Invalid JSON in header or payload: ' + e.message);
      return;
    }

    // Ensure the alg in the header matches the selected algorithm
    headerObj.alg = algorithm;
    // Update the header with the correct alg
    setHeader(JSON.stringify(headerObj, null, 2));

    setLoading(true);
    setError(null);

    try {
      const response = await axios.post('http://localhost:8000/generate', {
        header: headerObj,
        payload: payloadObj,
        secret,
        algorithm
      });

      setNewToken(response.data.token);
    } catch (err) {
      console.error('Error generating token:', err);
      
      if (err.response && err.response.data) {
        setError(err.response.data.error || 'Failed to generate token');
      } else {
        setError('Failed to connect to server. Please check if the backend is running.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="tool-container">
      <div className="tool-header">
        <h1>JWT Payload Editor</h1>
        <p>Edit JWT payload and generate new tokens.</p>
      </div>
      
      <div className="tool-content">
        <div className="form-group">
          <label htmlFor="token">
            Enter JWT Token (Optional):
          </label>
          <textarea
            id="token"
            className="form-control token-input"
            value={token}
            onChange={handleTokenChange}
            placeholder="Paste your JWT token here to decode and edit it"
            rows={3}
          />
          <div className="form-actions" style={{ marginTop: '10px' }}>
            <button 
              className="btn btn-outline-primary" 
              onClick={decodeToken}
            >
              Decode Token
            </button>
          </div>
        </div>
        
        <div className="form-group">
          <label htmlFor="header">Header:</label>
          <textarea
            id="header"
            className="form-control"
            value={header}
            onChange={handleHeaderChange}
            placeholder="Enter JWT header as JSON"
            rows={5}
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="payload">Payload:</label>
          <textarea
            id="payload"
            className="form-control"
            value={payload}
            onChange={handlePayloadChange}
            placeholder="Enter JWT payload as JSON"
            rows={8}
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="algorithm">Signature Algorithm:</label>
          <div className="algorithm-selector">
            {algorithms.map(alg => (
              <button
                key={alg.id}
                className={`algorithm-option ${algorithm === alg.id ? 'selected' : ''}`}
                onClick={() => selectAlgorithm(alg.id)}
              >
                {alg.name}
              </button>
            ))}
          </div>
        </div>
        
        {algorithm !== 'none' && (
          <div className="form-group">
            <label htmlFor="secret">
              {algorithm.startsWith('HS') ? 'Secret Key:' : 'Private Key:'}
            </label>
            <textarea
              id="secret"
              className="form-control"
              value={secret}
              onChange={handleSecretChange}
              placeholder={algorithm.startsWith('HS') 
                ? "Enter your secret key" 
                : "Enter your private key (PEM format)"}
              rows={3}
            />
          </div>
        )}
        
        <div className="form-actions">
          <button 
            className="btn btn-primary" 
            onClick={generateToken}
            disabled={loading}
          >
            {loading ? 'Generating...' : 'Generate Token'}
          </button>
        </div>
        
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}
        
        {newToken && (
          <div className="result-container">
            <div className="result-item">
              <h3>Generated Token</h3>
              <pre className="generated-token">{newToken}</pre>
              <button 
                className="btn btn-outline-primary"
                onClick={() => {
                  navigator.clipboard.writeText(newToken);
                }}
                style={{ marginTop: '10px' }}
              >
                Copy to Clipboard
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PayloadEditor; 