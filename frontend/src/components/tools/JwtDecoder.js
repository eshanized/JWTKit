import React, { useState } from 'react';
import '../Tools.css';

const JwtDecoder = () => {
  const [token, setToken] = useState('');
  const [decoded, setDecoded] = useState(null);
  const [error, setError] = useState(null);

  const handleTokenChange = (e) => {
    setToken(e.target.value);
    setError(null);
  };

  const handleDecode = () => {
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
        const header = JSON.parse(decodeBase64(parts[0]));
        const payload = JSON.parse(decodeBase64(parts[1]));
        
        setDecoded({
          header,
          payload,
          signature: parts[2]
        });
        
        setError(null);
      } catch (e) {
        setError('Error parsing JWT: ' + e.message);
      }
    } catch (e) {
      setError('Error decoding JWT: ' + e.message);
    }
  };

  return (
    <div className="tool-container">
      <div className="tool-header">
        <h1>JWT Decoder</h1>
        <p>Decode and inspect the contents of a JSON Web Token.</p>
      </div>
      
      <div className="tool-content">
        <div className="form-group">
          <label htmlFor="token">Enter JWT Token:</label>
          <textarea
            id="token"
            className="form-control token-input"
            value={token}
            onChange={handleTokenChange}
            placeholder="Paste your JWT token here"
            rows={4}
          />
        </div>
        
        <div className="form-actions">
          <button 
            className="btn btn-primary" 
            onClick={handleDecode}
          >
            Decode Token
          </button>
        </div>
        
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}
        
        {decoded && (
          <div className="result-container">
            <div className="result-item">
              <h3>Header</h3>
              <pre>{JSON.stringify(decoded.header, null, 2)}</pre>
            </div>
            
            <div className="result-item">
              <h3>Payload</h3>
              <pre>{JSON.stringify(decoded.payload, null, 2)}</pre>
              
              {decoded.payload.exp && (
                <div className="jwt-expiration">
                  <strong>Expiration: </strong>
                  {new Date(decoded.payload.exp * 1000).toLocaleString()}
                  {' '}
                  ({Date.now() > decoded.payload.exp * 1000 ? 'Expired' : 'Valid'})
                </div>
              )}
            </div>
            
            <div className="result-item">
              <h3>Signature (encoded)</h3>
              <pre className="signature">{decoded.signature}</pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default JwtDecoder; 