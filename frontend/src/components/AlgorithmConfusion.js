import React, { useState } from 'react';
import { Form, Button, Card, Alert } from 'react-bootstrap';
import axios from 'axios';

const AlgorithmConfusion = ({ token, onTokenChange }) => {
  const [publicKey, setPublicKey] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showExplanation, setShowExplanation] = useState(false);
  
  const executeAttack = async () => {
    if (!token.trim()) {
      setError('Please enter a JWT token first');
      return;
    }
    
    if (!publicKey.trim()) {
      setError('Please enter the public key');
      return;
    }
    
    setLoading(true);
    setError('');
    setResult(null);
    
    try {
      const response = await axios.post('http://localhost:8000/algorithm-confusion', {
        token,
        public_key: publicKey
      });
      
      setResult(response.data);
      
      // If attack was successful and we got a new token, update the parent component
      if (response.data.success && response.data.modified_token) {
        onTokenChange(response.data.modified_token);
      }
    } catch (err) {
      setError(`Attack failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div>
      <h2>Algorithm Confusion Attack</h2>
      <p>
        Test for the RS256 to HS256 algorithm confusion vulnerability
        <Button 
          variant="link" 
          className="p-0 ms-2" 
          onClick={() => setShowExplanation(!showExplanation)}
        >
          {showExplanation ? 'Hide explanation' : 'What is this?'}
        </Button>
      </p>
      
      {showExplanation && (
        <Alert variant="info">
          <h5>About Algorithm Confusion Attacks</h5>
          <p>
            This attack exploits implementations that don't properly validate the JWT algorithm. 
            It works by changing the algorithm from RSA (RS256) to HMAC (HS256) and using the 
            public key as the HMAC secret.
          </p>
          <p>
            In a vulnerable system, the token verification code might accept the algorithm 
            specified in the token's header and use the same key for both RSA and HMAC verification.
          </p>
          <p className="mb-0">
            <strong>Attack process:</strong>
            <ol className="mb-0">
              <li>Start with a valid RS256 token</li>
              <li>Change the algorithm in the header from RS256 to HS256</li>
              <li>Re-sign the token using the public key as the HMAC secret</li>
              <li>If the system doesn't check algorithms properly, it will accept the forged token</li>
            </ol>
          </p>
        </Alert>
      )}
      
      {!token && (
        <Alert variant="info">
          Enter a JWT token in the decoder tab to use this attack. The token should use the RS256 algorithm.
        </Alert>
      )}
      
      <Form>
        <Form.Group className="mb-3">
          <Form.Label>Public Key (PEM format)</Form.Label>
          <Form.Control
            as="textarea"
            rows={5}
            value={publicKey}
            onChange={(e) => setPublicKey(e.target.value)}
            placeholder="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----"
          />
          <Form.Text className="text-muted">
            Enter the RSA public key in PEM format. This is the key used to verify the original RS256 token.
          </Form.Text>
        </Form.Group>
        
        <Button
          variant="danger"
          onClick={executeAttack}
          disabled={loading || !token.trim() || !publicKey.trim()}
        >
          {loading ? 'Executing Attack...' : 'Execute Algorithm Confusion Attack'}
        </Button>
      </Form>
      
      {error && (
        <Alert variant="danger" className="mt-3">
          {error}
        </Alert>
      )}
      
      {result && (
        <Card className="mt-4">
          <Card.Header className={result.success ? "bg-success text-white" : "bg-warning text-white"}>
            <strong>Attack Result</strong>
          </Card.Header>
          <Card.Body>
            {result.success ? (
              <>
                <Alert variant="success">
                  <i className="bi bi-check-circle-fill me-2"></i>
                  Attack executed successfully! A new forged token has been generated.
                </Alert>
                
                <div className="mt-3">
                  <h5>Forged Token:</h5>
                  <div className="border p-3 bg-light text-break">
                    <small>{result.modified_token}</small>
                  </div>
                  
                  <Alert variant="warning" className="mt-3">
                    <strong>Note:</strong> This token has been set as the active token. 
                    You can now try to verify it or test it against an endpoint.
                  </Alert>
                </div>
              </>
            ) : (
              <Alert variant="warning">
                <i className="bi bi-exclamation-triangle-fill me-2"></i>
                Attack could not be executed: {result.error}
              </Alert>
            )}
            
            {result.description && (
              <div className="mt-3">
                <h5>Attack Details:</h5>
                <p>{result.description}</p>
              </div>
            )}
          </Card.Body>
        </Card>
      )}
    </div>
  );
};

export default AlgorithmConfusion; 