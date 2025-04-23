import React, { useState } from 'react';
import { Form, Button, Card, Alert, InputGroup } from 'react-bootstrap';
import axios from 'axios';

const SignatureVerifier = ({ token }) => {
  const [secret, setSecret] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [algorithm, setAlgorithm] = useState('HS256');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [keysLoading, setKeysLoading] = useState(false);
  const [error, setError] = useState('');

  const algorithms = [
    { value: 'HS256', label: 'HS256 (HMAC + SHA256)' },
    { value: 'HS384', label: 'HS384 (HMAC + SHA384)' },
    { value: 'HS512', label: 'HS512 (HMAC + SHA512)' },
    { value: 'RS256', label: 'RS256 (RSA + SHA256)' },
    { value: 'RS384', label: 'RS384 (RSA + SHA384)' },
    { value: 'RS512', label: 'RS512 (RSA + SHA512)' },
    { value: 'PS256', label: 'PS256 (RSA-PSS + SHA256)' },
    { value: 'PS384', label: 'PS384 (RSA-PSS + SHA384)' },
    { value: 'PS512', label: 'PS512 (RSA-PSS + SHA512)' },
    { value: 'ES256', label: 'ES256 (ECDSA + SHA256)' },
    { value: 'ES384', label: 'ES384 (ECDSA + SHA384)' },
    { value: 'ES512', label: 'ES512 (ECDSA + SHA512)' },
    { value: 'EdDSA', label: 'EdDSA (Ed25519)' }
  ];

  const isAsymmetric = algorithm => {
    return algorithm.startsWith('RS') || 
           algorithm.startsWith('PS') || 
           algorithm.startsWith('ES') || 
           algorithm === 'EdDSA';
  };

  const fetchSampleKeys = async () => {
    try {
      setKeysLoading(true);
      setError('');
      const response = await axios.get('http://localhost:8000/generate-sample-keys');
      
      // Select the appropriate key based on the current algorithm
      const keys = response.data;
      if (keys[algorithm]) {
        if (algorithm.startsWith('HS')) {
          setSecret(keys[algorithm].secret);
        } else if (isAsymmetric(algorithm)) {
          // For verifying, we need the public key
          setPublicKey(keys[algorithm].public_key);
        }
      }
    } catch (err) {
      setError(`Failed to fetch sample keys: ${err.message}`);
    } finally {
      setKeysLoading(false);
    }
  };

  const verifySignature = async () => {
    if (!token.trim()) {
      setError('Please enter a JWT token first');
      return;
    }

    const needsSecretOrKey = !isAsymmetric(algorithm) && !secret.trim() ||
                             isAsymmetric(algorithm) && !publicKey.trim();
                             
    if (needsSecretOrKey) {
      setError('Please enter a key for verification');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const requestData = {
        token,
        algorithm
      };
      
      // Add the appropriate key to the request
      if (isAsymmetric(algorithm)) {
        requestData.public_key = publicKey.trim();
      } else {
        requestData.secret = secret.trim();
      }
      
      const response = await axios.post('http://localhost:8000/verify', requestData);
      
      setResult(response.data);
    } catch (err) {
      setError(`Verification failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2>JWT Signature Verifier</h2>
      <p>Verify the signature of a JWT using your secret key</p>
      
      {!token && (
        <Alert variant="info">
          Enter a JWT in the decoder tab to verify its signature
        </Alert>
      )}
      
      <Form>
        <Form.Group className="mb-3">
          <Form.Label>Algorithm</Form.Label>
          <Form.Select
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
          >
            {algorithms.map((alg) => (
              <option key={alg.value} value={alg.value}>
                {alg.label}
              </option>
            ))}
          </Form.Select>
          <Form.Text className="text-muted">
            Select the algorithm used to sign the token
          </Form.Text>
        </Form.Group>
        
        <Form.Group className="mb-3">
          <Form.Label>
            {isAsymmetric(algorithm) 
              ? 'Public Key' 
              : 'Secret Key'}
          </Form.Label>
          <InputGroup className="mb-3">
            <Form.Control
              as="textarea"
              rows={3}
              value={isAsymmetric(algorithm) ? publicKey : secret}
              onChange={(e) => isAsymmetric(algorithm) ? setPublicKey(e.target.value) : setSecret(e.target.value)}
              placeholder={isAsymmetric(algorithm) 
                ? "Enter your public key in PEM format..." 
                : "Enter your HMAC secret key..."}
            />
            <Button 
              variant="outline-secondary"
              onClick={fetchSampleKeys}
              disabled={keysLoading}
            >
              {keysLoading ? 'Generating...' : 'Generate Sample Key'}
            </Button>
          </InputGroup>
          <Form.Text className="text-muted">
            {isAsymmetric(algorithm)
              ? "For RSA/ECDSA/EdDSA algorithms, enter the public key in PEM format"
              : "For HMAC algorithms, enter the shared secret key"}
          </Form.Text>
        </Form.Group>
        
        <Button
          variant="primary"
          onClick={verifySignature}
          disabled={loading || !token.trim() || (isAsymmetric(algorithm) ? !publicKey.trim() : !secret.trim())}
        >
          {loading ? 'Verifying...' : 'Verify Signature'}
        </Button>
      </Form>
      
      {error && (
        <Alert variant="danger" className="mt-3">
          {error}
        </Alert>
      )}
      
      {result && (
        <Card className="mt-4">
          <Card.Header className={result.valid ? "bg-success text-white" : "bg-danger text-white"}>
            <strong>Verification Result</strong>
          </Card.Header>
          <Card.Body>
            {result.valid ? (
              <>
                <Alert variant="success">
                  <i className="bi bi-check-circle-fill me-2"></i>
                  Signature is valid! The token was signed with the provided key.
                </Alert>
                
                {result.payload && (
                  <div className="mt-3">
                    <h5>Verified Payload:</h5>
                    <pre>{JSON.stringify(result.payload, null, 2)}</pre>
                  </div>
                )}
              </>
            ) : (
              <Alert variant="danger">
                <i className="bi bi-x-circle-fill me-2"></i>
                Signature verification failed: {result.error || 'Invalid signature'}
              </Alert>
            )}
          </Card.Body>
        </Card>
      )}
    </div>
  );
};

export default SignatureVerifier;