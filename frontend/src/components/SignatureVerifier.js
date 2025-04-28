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
