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
