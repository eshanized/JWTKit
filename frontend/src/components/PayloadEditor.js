import React, { useState, useEffect } from 'react';
import { Form, Button, Card, Alert, Row, Col, InputGroup } from 'react-bootstrap';
import axios from 'axios';

const PayloadEditor = ({ token, onTokenChange }) => {
  const [header, setHeader] = useState({});
  const [payload, setPayload] = useState({});
  const [payloadJson, setPayloadJson] = useState('');
  const [secret, setSecret] = useState('');
  const [algorithm, setAlgorithm] = useState('HS256');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [jsonError, setJsonError] = useState('');
  const [keysLoading, setKeysLoading] = useState(false);

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
    { value: 'EdDSA', label: 'EdDSA (Ed25519)' },
    { value: 'none', label: 'none (No signature)' }
  ];

  // Templates for common payloads
  const templates = [
    { 
      name: 'Admin Role',
      payload: { 
        sub: '1234567890',
        name: 'John Doe',
        role: 'admin',
        isAdmin: true,
        permissions: ['read', 'write', 'delete', 'admin']
      }
    },
    { 
      name: 'Never Expires',
      payload: { 
        sub: '1234567890',
        name: 'John Doe',
        role: 'user',
        exp: 9999999999  // Very far in the future
      }
    },
    { 
      name: 'All Access',
      payload: { 
        sub: 'superuser',
        name: 'System User',
        access_level: 'all',
        bypass_security: true,
        // Some CVEs are related to specific claim names
        auth_level: 9,
        debug: true,
        debug_admin: true
      }
    }
  ];

  useEffect(() => {
    if (token) {
      decodeToken();
    }
  }, [token]);

  const decodeToken = () => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }

      const decodedHeader = JSON.parse(atob(parts[0]));
      const decodedPayload = JSON.parse(atob(parts[1]));
      
      setHeader(decodedHeader);
      setPayload(decodedPayload);
      setPayloadJson(JSON.stringify(decodedPayload, null, 2));
      
      // Set algorithm based on the header
      if (decodedHeader.alg) {
        setAlgorithm(decodedHeader.alg);
      }
    } catch (e) {
      setError(`Error decoding token: ${e.message}`);
    }
  };

  const applyTemplate = (template) => {
    const newPayload = {
      ...template.payload
    };
    setPayload(newPayload);
    setPayloadJson(JSON.stringify(newPayload, null, 2));
  };

  const updatePayloadFromJson = (jsonString) => {
    setPayloadJson(jsonString);
    setJsonError('');
    
    try {
      const parsed = JSON.parse(jsonString);
      setPayload(parsed);
    } catch (e) {
      setJsonError('Invalid JSON: ' + e.message);
    }
  };

  const generateToken = async () => {
    if (jsonError) {
      setError('Please fix the JSON errors before generating a token');
      return;
    }

    // Only require secret for algorithms that need signing
    if (algorithm !== 'none' && !secret.trim()) {
      setError('Please enter a secret key for signing');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const requestData = {
        token,
        new_payload: payload,
        algorithm
      };

      // Add the appropriate key field based on algorithm type
      if (algorithm.startsWith('HS')) {
        requestData.secret = secret.trim();
      } else if (algorithm !== 'none') {
        requestData.private_key = secret.trim();
      }

      const response = await axios.post('http://localhost:8000/modify', requestData);
      
      setResult(response.data);
      
      // If we got a new token, update the parent component
      if (response.data.modified_token) {
        onTokenChange(response.data.modified_token);
      }
    } catch (err) {
      setError(`Error generating token: ${err.response?.data?.detail || err.message}`);
    } finally {
      setLoading(false);
    }
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
        } else if (algorithm !== 'none') {
          setSecret(keys[algorithm].private_key);
        }
      }
    } catch (err) {
      setError(`Failed to fetch sample keys: ${err.message}`);
    } finally {
      setKeysLoading(false);
    }
  };

  return (
    <div>
      <h2>JWT Payload Editor</h2>
      <p>Modify token claims and generate new tokens</p>
      
      {!token && (
        <Alert variant="info">
          Enter a JWT in the decoder tab to modify its payload
        </Alert>
      )}
      
      {error && (
        <Alert variant="danger">
          {error}
        </Alert>
      )}
      
      {token && (
        <Row>
          <Col md={8}>
            <Form.Group className="mb-3">
              <Form.Label>Payload (JSON)</Form.Label>
              <Form.Control
                as="textarea"
                rows={10}
                value={payloadJson}
                onChange={(e) => updatePayloadFromJson(e.target.value)}
                isInvalid={!!jsonError}
                className="font-monospace"
              />
              {jsonError && (
                <Form.Control.Feedback type="invalid">
                  {jsonError}
                </Form.Control.Feedback>
              )}
            </Form.Group>
          </Col>
          
          <Col md={4}>
            <Card className="mb-3">
              <Card.Header>Template Payloads</Card.Header>
              <Card.Body>
                <p className="text-muted small">Click on a template to apply it</p>
                {templates.map((template, index) => (
                  <Button
                    key={index}
                    variant="outline-secondary"
                    className="mb-2 me-2"
                    onClick={() => applyTemplate(template)}
                  >
                    {template.name}
                  </Button>
                ))}
              </Card.Body>
            </Card>
            
            <Card>
              <Card.Header>Common Claims</Card.Header>
              <Card.Body>
                <p className="text-muted small">Click to add common claims</p>
                <Button
                  variant="outline-primary"
                  size="sm"
                  className="mb-2 me-2"
                  onClick={() => {
                    const updatedPayload = { ...payload, admin: true };
                    setPayload(updatedPayload);
                    setPayloadJson(JSON.stringify(updatedPayload, null, 2));
                  }}
                >
                  admin: true
                </Button>
                
                <Button
                  variant="outline-primary"
                  size="sm"
                  className="mb-2 me-2"
                  onClick={() => {
                    const updatedPayload = { ...payload, role: 'admin' };
                    setPayload(updatedPayload);
                    setPayloadJson(JSON.stringify(updatedPayload, null, 2));
                  }}
                >
                  role: admin
                </Button>
                
                <Button
                  variant="outline-primary"
                  size="sm"
                  className="mb-2 me-2"
                  onClick={() => {
                    // Set expiration to 100 years from now
                    const updatedPayload = { 
                      ...payload, 
                      exp: Math.floor(Date.now() / 1000) + (3600 * 24 * 365 * 100)
                    };
                    setPayload(updatedPayload);
                    setPayloadJson(JSON.stringify(updatedPayload, null, 2));
                  }}
                >
                  exp: +100 years
                </Button>
                
                <Button
                  variant="outline-primary"
                  size="sm"
                  className="mb-2 me-2"
                  onClick={() => {
                    // Remove exp claim if exists
                    const { exp, ...rest } = payload;
                    setPayload(rest);
                    setPayloadJson(JSON.stringify(rest, null, 2));
                  }}
                >
                  Remove exp
                </Button>
              </Card.Body>
            </Card>
          </Col>
        </Row>
      )}
      
      {token && (
        <Card className="mt-3 mb-3">
          <Card.Header>Signature Settings</Card.Header>
          <Card.Body>
            <Row>
              <Col md={6}>
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
                    Select the algorithm to use for signing the token
                  </Form.Text>
                </Form.Group>
              </Col>
              
              {algorithm !== 'none' && (
                <Col md={6}>
                  <Form.Group className="mb-3">
                    <Form.Label>
                      {algorithm.startsWith('HS') 
                        ? 'Secret Key' 
                        : 'Private Key'}
                    </Form.Label>
                    <InputGroup>
                      <Form.Control
                        as="textarea"
                        rows={5}
                        value={secret}
                        onChange={(e) => setSecret(e.target.value)}
                        placeholder={algorithm.startsWith('HS') 
                          ? "Enter your secret key..." 
                          : "Enter your private key in PEM format..."}
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
                      {algorithm.startsWith('HS')
                        ? "For HMAC algorithms, enter your secret key"
                        : "For RSA/ECDSA/EdDSA algorithms, enter your private key in PEM format"}
                    </Form.Text>
                  </Form.Group>
                </Col>
              )}
            </Row>
            
            <Button
              variant="primary"
              onClick={generateToken}
              disabled={loading || jsonError || (algorithm !== 'none' && !secret.trim())}
            >
              {loading ? 'Generating...' : 'Generate New Token'}
            </Button>
          </Card.Body>
        </Card>
      )}
      
      {result && (
        <Card className="mt-4">
          <Card.Header className="bg-success text-white">
            <strong>New Token Generated</strong>
          </Card.Header>
          <Card.Body>
            <Alert variant="success">
              <i className="bi bi-check-circle-fill me-2"></i>
              Token successfully generated with {result.algorithm} algorithm
            </Alert>
            
            <div className="mt-3">
              <h5>Modified Token:</h5>
              <div className="border p-3 bg-light text-break">
                <small>{result.modified_token}</small>
              </div>
              
              {result.warning && (
                <Alert variant="warning" className="mt-3">
                  <strong>Warning:</strong> {result.warning}
                </Alert>
              )}
              
              <Alert variant="info" className="mt-3">
                <strong>Note:</strong> This token has been set as the active token. 
                You can now test it against an endpoint.
              </Alert>
            </div>
          </Card.Body>
        </Card>
      )}
    </div>
  );
};

export default PayloadEditor;