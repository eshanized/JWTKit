import React, { useState } from 'react';
import { Form, Button, Card, Alert, InputGroup } from 'react-bootstrap';
import axios from 'axios';

const SignatureVerifier = ({ token }) => {
  const [secret, setSecret] = useState('');
  const [algorithm, setAlgorithm] = useState('HS256');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const algorithms = [
    { value: 'HS256', label: 'HS256 (HMAC + SHA256)' },
    { value: 'HS384', label: 'HS384 (HMAC + SHA384)' },
    { value: 'HS512', label: 'HS512 (HMAC + SHA512)' },
    { value: 'RS256', label: 'RS256 (RSA + SHA256)' },
    { value: 'RS384', label: 'RS384 (RSA + SHA384)' },
    { value: 'RS512', label: 'RS512 (RSA + SHA512)' },
    { value: 'ES256', label: 'ES256 (ECDSA + SHA256)' },
    { value: 'ES384', label: 'ES384 (ECDSA + SHA384)' },
    { value: 'ES512', label: 'ES512 (ECDSA + SHA512)' }
  ];

  const verifySignature = async () => {
    if (!token.trim()) {
      setError('Please enter a JWT token first');
      return;
    }

    if (!secret.trim()) {
      setError('Please enter a secret key');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post('http://localhost:8000/verify', {
        token,
        secret,
        algorithm
      });
      
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
          <Form.Label>Secret Key / Private Key</Form.Label>
          <InputGroup className="mb-3">
            <Form.Control
              as="textarea"
              rows={3}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={algorithm.startsWith('HS') 
                ? "Enter your HMAC secret key..." 
                : "Enter your private key in PEM format..."}
            />
          </InputGroup>
          <Form.Text className="text-muted">
            {algorithm.startsWith('HS')
              ? "For HMAC algorithms, enter the shared secret key"
              : "For RSA/ECDSA algorithms, enter the private key in PEM format"}
          </Form.Text>
        </Form.Group>
        
        <Button
          variant="primary"
          onClick={verifySignature}
          disabled={loading || !token.trim() || !secret.trim()}
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
                  Signature is valid! The token was signed with the provided secret key.
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