import React, { useState, useEffect } from 'react';
import { Form, Button, Card, Alert, Row, Col } from 'react-bootstrap';
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

  const algorithms = [
    { value: 'HS256', label: 'HS256 (HMAC + SHA256)' },
    { value: 'HS384', label: 'HS384 (HMAC + SHA384)' },
    { value: 'HS512', label: 'HS512 (HMAC + SHA512)' },
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
      const response = await axios.post('http://localhost:8000/modify', {
        token,
        new_payload: payload,
        secret: secret.trim() || undefined,
        algorithm
      });
      
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
                </Form.Group>
              </Col>
              
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>
                    {algorithm === 'none' ? 'No Secret Needed' : 'Secret Key'}
                  </Form.Label>
                  <Form.Control
                    type="text"
                    placeholder={algorithm === 'none' 
                      ? 'No secret required for none algorithm' 
                      : 'Enter your secret key for signing'}
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                    disabled={algorithm === 'none'}
                  />
                </Form.Group>
              </Col>
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