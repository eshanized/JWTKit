import React, { useState } from 'react';
import { Form, Button, Card, Alert, InputGroup, Row, Col } from 'react-bootstrap';
import axios from 'axios';
import ValidationFeedback from './ValidationFeedback';

const TokenTester = ({ token }) => {
  const [url, setUrl] = useState('');
  const [method, setMethod] = useState('GET');
  const [headerName, setHeaderName] = useState('Authorization');
  const [headerValue, setHeaderValue] = useState('Bearer {token}');
  const [additionalHeaders, setAdditionalHeaders] = useState({});
  const [body, setBody] = useState('');
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [validationResults, setValidationResults] = useState([]);
  const [isLoading, setIsLoading] = useState(false);

  const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

  const testToken = async () => {
    if (!token.trim()) {
      setError('Please enter a JWT token first');
      return;
    }

    if (!url.trim()) {
      setError('Please enter a target URL');
      return;
    }

    setLoading(true);
    setError('');
    setResponse(null);

    // Replace {token} placeholder with actual token
    const finalHeaderValue = headerValue.replace('{token}', token);
    
    // Build headers
    const headers = {
      ...additionalHeaders,
      [headerName]: finalHeaderValue
    };

    try {
      // This would normally be done via the backend to avoid CORS issues
      // For demo purposes, we're doing it directly from the frontend
      let options = {
        method,
        url,
        headers,
        timeout: 10000 // 10 second timeout
      };
      
      if (method !== 'GET' && body.trim()) {
        try {
          // Try to parse as JSON first
          const jsonBody = JSON.parse(body);
          options.data = jsonBody;
        } catch (e) {
          // If not valid JSON, send as raw text
          options.data = body;
        }
      }
      
      const res = await axios(options);
      
      setResponse({
        status: res.status,
        statusText: res.statusText,
        headers: res.headers,
        data: res.data
      });
    } catch (err) {
      if (err.response) {
        // Server responded with a status code outside of 2xx
        setResponse({
          status: err.response.status,
          statusText: err.response.statusText,
          headers: err.response.headers,
          data: err.response.data
        });
      } else {
        setError(`Request failed: ${err.message}`);
      }
    } finally {
      setLoading(false);
    }
  };

  const validateToken = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:8000/test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token })
      });
      
      const data = await response.json();
      if (data.validation_results) {
        setValidationResults(data.validation_results);
      }
    } catch (error) {
      console.error('Error validating token:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const getStatusBadge = (status) => {
    let variant = 'secondary';
    
    if (status >= 200 && status < 300) {
      variant = 'success';
    } else if (status >= 300 && status < 400) {
      variant = 'info';
    } else if (status >= 400 && status < 500) {
      variant = 'warning';
    } else if (status >= 500) {
      variant = 'danger';
    }
    
    return (
      <span className={`badge bg-${variant}`}>
        {status}
      </span>
    );
  };

  return (
    <div>
      <Row>
        <Col md={6}>
          <Card className="mb-4">
            <Card.Header>
              <h5 className="mb-0">Token Security Tester</h5>
            </Card.Header>
            <Card.Body>
              <Form>
                <Form.Group className="mb-3">
                  <Form.Label>JWT Token</Form.Label>
                  <Form.Control
                    as="textarea"
                    rows={3}
                    value={token}
                    readOnly
                    placeholder="Enter or paste a JWT token to test"
                  />
                </Form.Group>
                <Button 
                  variant="primary" 
                  onClick={validateToken}
                  disabled={!token || isLoading}
                >
                  {isLoading ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                      Testing...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-shield-alt me-2"></i>
                      Test Token Security
                    </>
                  )}
                </Button>
              </Form>
            </Card.Body>
          </Card>
        </Col>
        <Col md={6}>
          <ValidationFeedback 
            token={token} 
            validationResults={validationResults}
          />
        </Col>
      </Row>
      <h2>JWT Token Tester</h2>
      <p>Test your JWT token against a real endpoint</p>
      
      {!token && (
        <Alert variant="info">
          Enter a JWT in the decoder tab to test it against an endpoint
        </Alert>
      )}
      
      <Form>
        <Form.Group className="mb-3">
          <Form.Label>Target URL</Form.Label>
          <Form.Control
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://api.example.com/protected-endpoint"
          />
          <Form.Text className="text-muted">
            Enter the full URL of the API endpoint to test
          </Form.Text>
        </Form.Group>
        
        <Form.Group className="mb-3">
          <Form.Label>HTTP Method</Form.Label>
          <Form.Select
            value={method}
            onChange={(e) => setMethod(e.target.value)}
          >
            {httpMethods.map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </Form.Select>
        </Form.Group>
        
        <Form.Group className="mb-3">
          <Form.Label>Authorization Header</Form.Label>
          <InputGroup>
            <Form.Control
              placeholder="Header name"
              value={headerName}
              onChange={(e) => setHeaderName(e.target.value)}
            />
            <Form.Control
              placeholder="Header value"
              value={headerValue}
              onChange={(e) => setHeaderValue(e.target.value)}
            />
          </InputGroup>
          <Form.Text className="text-muted">
            Use {'{token}'} as placeholder for your JWT. Default: "Bearer {token}"
          </Form.Text>
        </Form.Group>
        
        {method !== 'GET' && (
          <Form.Group className="mb-3">
            <Form.Label>Request Body (optional)</Form.Label>
            <Form.Control
              as="textarea"
              rows={3}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Enter request body (JSON or plain text)"
            />
          </Form.Group>
        )}
        
        <Button
          variant="primary"
          onClick={testToken}
          disabled={loading || !token.trim() || !url.trim()}
        >
          {loading ? 'Sending Request...' : 'Test Token'}
        </Button>
      </Form>
      
      {error && (
        <Alert variant="danger" className="mt-3">
          {error}
        </Alert>
      )}
      
      {response && (
        <Card className="mt-4">
          <Card.Header className="d-flex justify-content-between align-items-center">
            <strong>Response</strong>
            <div>
              {getStatusBadge(response.status)} {response.statusText}
            </div>
          </Card.Header>
          <Card.Body>
            <div className="mb-3">
              <h5>Response Headers:</h5>
              <pre className="bg-light p-2">{JSON.stringify(response.headers, null, 2)}</pre>
            </div>
            
            <div>
              <h5>Response Body:</h5>
              <pre className="bg-light p-2">{
                typeof response.data === 'object' 
                  ? JSON.stringify(response.data, null, 2) 
                  : String(response.data)
              }</pre>
            </div>
            
            <Alert 
              variant={response.status >= 200 && response.status < 300 ? 'success' : 'warning'} 
              className="mt-3"
            >
              {response.status >= 200 && response.status < 300 
                ? "Token was accepted by the server!"
                : "Token was rejected or request failed."}
            </Alert>
          </Card.Body>
        </Card>
      )}
    </div>
  );
};

export default TokenTester;