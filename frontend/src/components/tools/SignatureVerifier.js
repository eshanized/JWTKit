import React, { useState } from 'react';
import axios from 'axios';
import '../Tools.css';

const SignatureVerifier = () => {
  const [token, setToken] = useState('');
  const [secret, setSecret] = useState('');
  const [algorithm, setAlgorithm] = useState('HS256');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const algorithms = [
    { id: 'HS256', name: 'HS256', family: 'HMAC' },
    { id: 'HS384', name: 'HS384', family: 'HMAC' },
    { id: 'HS512', name: 'HS512', family: 'HMAC' },
    { id: 'RS256', name: 'RS256', family: 'RSA' },
    { id: 'RS384', name: 'RS384', family: 'RSA' },
    { id: 'RS512', name: 'RS512', family: 'RSA' }
  ];

  const handleTokenChange = (e) => {
    setToken(e.target.value);
    setError(null);
    setResult(null);
  };

  const handleSecretChange = (e) => {
    setSecret(e.target.value);
    setError(null);
  };

  const selectAlgorithm = (alg) => {
    setAlgorithm(alg);
    setError(null);
  };

  const verifySignature = async () => {
    if (!token.trim()) {
      setError('Please enter a JWT token');
      return;
    }

    if (!secret.trim()) {
      setError('Please enter a secret key');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await axios.post('http://localhost:8000/verify', {
        token,
        secret,
        algorithm
      });

      setResult(response.data);
    } catch (err) {
      console.error('Error verifying signature:', err);
      
      if (err.response && err.response.data) {
        setError(err.response.data.error || 'Failed to verify signature');
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
        <h1>JWT Signature Verifier</h1>
        <p>Verify the signature of a JWT using a secret key or certificate.</p>
      </div>
      
      <div className="tool-content">
        <div className="form-group">
          <label htmlFor="token">JWT Token:</label>
          <textarea
            id="token"
            className="form-control token-input"
            value={token}
            onChange={handleTokenChange}
            placeholder="Paste your JWT token here"
            rows={4}
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
        
        <div className="form-group">
          <label htmlFor="secret">
            {algorithm.startsWith('HS') ? 'Secret Key:' : 'Public Key/Certificate:'}
          </label>
          <textarea
            id="secret"
            className="form-control"
            value={secret}
            onChange={handleSecretChange}
            placeholder={algorithm.startsWith('HS') 
              ? "Enter your secret key" 
              : "Enter your public key or certificate (PEM format)"}
            rows={5}
          />
        </div>
        
        <div className="form-actions">
          <button 
            className="btn btn-primary" 
            onClick={verifySignature}
            disabled={loading}
          >
            {loading ? 'Verifying...' : 'Verify Signature'}
          </button>
        </div>
        
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}
        
        {result && (
          <div className="result-container">
            {result.valid ? (
              <div className="success-message">
                <h3>✓ Signature is valid</h3>
                <div className="result-item">
                  <h3>Payload</h3>
                  <pre>{JSON.stringify(result.payload, null, 2)}</pre>
                </div>
              </div>
            ) : (
              <div className="error-message">
                <h3>✗ Invalid signature</h3>
                <p>{result.error || 'The signature could not be verified with the provided key.'}</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default SignatureVerifier; 