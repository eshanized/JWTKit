import React, { useState, useEffect } from 'react';
import { Card, Form, Button, Row, Col, Badge } from 'react-bootstrap';
import axios from 'axios';

const JwtDecoder = ({ token = '', onTokenChange }) => {
  const [inputToken, setInputToken] = useState(token);
  const [header, setHeader] = useState({});
  const [payload, setPayload] = useState({});
  const [signature, setSignature] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setInputToken(token);
  }, [token]);

  useEffect(() => {
    if (inputToken) {
      decodeToken();
    }
  }, []);

  const decodeToken = async () => {
    if (!inputToken || !inputToken.trim()) {
      setError('Please enter a JWT token');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // First try to decode locally, as a fallback
      const localDecode = () => {
        try {
          const parts = inputToken.split('.');
          if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
          }

          const decodedHeader = JSON.parse(atob(parts[0]));
          const decodedPayload = JSON.parse(atob(parts[1]));
          
          setHeader(decodedHeader);
          setPayload(decodedPayload);
          setSignature(parts[2]);
          setError('');
        } catch (e) {
          setError(`Error decoding token: ${e.message}`);
        }
      };

      // Try to use backend for decoding
      try {
        const response = await axios.post('http://localhost:8000/decode', { token: inputToken });
        setHeader(response.data.header);
        setPayload(response.data.payload);
        // Check if signature is an object and extract the raw value
        if (response.data.signature && typeof response.data.signature === 'object') {
          setSignature(response.data.signature.raw || '');
        } else {
          setSignature(response.data.signature || '');
        }
      } catch (err) {
        // Fallback to local decoding if backend is not available
        localDecode();
      }
    } catch (err) {
      setError(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleTokenInput = (e) => {
    const newToken = e.target.value;
    setInputToken(newToken);
    if (onTokenChange) {
      onTokenChange(newToken);
    }
  };

  const formatJson = (obj) => {
    return JSON.stringify(obj, null, 2);
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp || isNaN(timestamp)) return 'Invalid timestamp';
    
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
  };

  const getClaimBadge = (key, value) => {
    // Special display for common claims
    switch (key) {
      case 'exp':
        return (
          <Badge bg="info">
            Expires: {formatTimestamp(value)}
          </Badge>
        );
      case 'iat':
        return (
          <Badge bg="secondary">
            Issued: {formatTimestamp(value)}
          </Badge>
        );
      case 'nbf':
        return (
          <Badge bg="warning">
            Not Before: {formatTimestamp(value)}
          </Badge>
        );
      case 'iss':
        return (
          <Badge bg="primary">
            Issuer: {value}
          </Badge>
        );
      case 'sub':
        return (
          <Badge bg="success">
            Subject: {value}
          </Badge>
        );
      case 'aud':
        return (
          <Badge bg="dark">
            Audience: {Array.isArray(value) ? value.join(', ') : value}
          </Badge>
        );
      default:
        return null;
    }
  };

  return (
    <div>
      <h2>JWT Decoder & Inspector</h2>
      <p>Decode and analyze JSON Web Tokens (JWTs)</p>
      
      <Form>
        <Form.Group className="mb-3">
          <Form.Label>Enter JWT Token</Form.Label>
          <Form.Control
            as="textarea"
            rows={3}
            value={inputToken}
            onChange={handleTokenInput}
            placeholder="Paste your JWT token here..."
          />
        </Form.Group>
        <Button 
          variant="primary" 
          onClick={decodeToken} 
          disabled={loading || !inputToken || !inputToken.trim()}
        >
          {loading ? 'Decoding...' : 'Decode Token'}
        </Button>
      </Form>

      {error && (
        <div className="alert alert-danger mt-3">
          {error}
        </div>
      )}

      {!error && Object.keys(header).length > 0 && (
        <div className="mt-4">
          <Row>
            <Col md={6}>
              <Card className="mb-3">
                <Card.Header className="bg-primary text-white">
                  <strong>Header</strong>
                </Card.Header>
                <Card.Body>
                  <pre className="mb-0">{formatJson(header)}</pre>
                </Card.Body>
                <Card.Footer>
                  <Badge bg={header.alg === 'none' ? 'danger' : (header.alg?.startsWith('HS') ? 'warning' : 'success')}>
                    Algorithm: {header.alg}
                  </Badge>
                </Card.Footer>
              </Card>
            </Col>
            
            <Col md={6}>
              <Card className="mb-3">
                <Card.Header className="bg-success text-white">
                  <strong>Signature</strong>
                </Card.Header>
                <Card.Body>
                  <div className="text-break">
                    <small>{signature}</small>
                    {typeof signature === 'object' && (
                      <div className="mt-2">
                        <Badge bg="info">Size: {signature.size_bytes} bytes</Badge>
                      </div>
                    )}
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>
          
          <Card className="mb-3">
            <Card.Header className="bg-info text-white">
              <strong>Payload (Claims)</strong>
            </Card.Header>
            <Card.Body>
              <pre>{formatJson(payload)}</pre>
            </Card.Body>
            <Card.Footer>
              <div className="d-flex flex-wrap gap-2">
                {Object.entries(payload).map(([key, value]) => {
                  const badge = getClaimBadge(key, value);
                  return badge ? (
                    <div key={key}>{badge}</div>
                  ) : null;
                })}
              </div>
            </Card.Footer>
          </Card>
        </div>
      )}
    </div>
  );
};

export default JwtDecoder;