import React, { useState } from 'react';
import { Card, Form, Button, ListGroup, Badge, Alert, Row, Col } from 'react-bootstrap';

const TokenFuzzer = ({ token }) => {
  const [fuzzResults, setFuzzResults] = useState([]);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [selectedPayloads, setSelectedPayloads] = useState({
    sql_injection: true,
    path_traversal: true,
    command_injection: true,
    jwt_attacks: true,
    null_byte: true
  });

  const fuzzingPayloads = {
    sql_injection: [
      "' OR '1'='1",
      "admin' --",
      "' UNION SELECT * FROM users--",
      "1'; DROP TABLE users--"
    ],
    path_traversal: [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32",
      "%2e%2e%2f%2e%2e%2f",
      "/dev/null"
    ],
    command_injection: [
      "; cat /etc/passwd",
      "| whoami",
      "`id`",
      "$(cat /etc/shadow)"
    ],
    jwt_attacks: [
      '{"alg":"none"}',
      '{"alg":"HS256","kid":"../../dev/null"}',
      '{"alg":"RS256","x5u":"http://evil.com/key.pem"}'
    ],
    null_byte: [
      "%00",
      "\\x00",
      "\u0000",
      "\x00"
    ]
  };

  const modifyToken = (originalToken, payload, location) => {
    try {
      const [header, body, signature] = originalToken.split('.');
      const decodedHeader = JSON.parse(atob(header));
      const decodedBody = JSON.parse(atob(body));

      if (location === 'header') {
        // Modify header fields
        Object.entries(payload).forEach(([key, value]) => {
          decodedHeader[key] = value;
        });
      } else if (location === 'payload') {
        // Inject payload into various claims
        ['sub', 'name', 'role', 'scope'].forEach(claim => {
          if (decodedBody[claim]) {
            decodedBody[claim] = payload;
          }
        });
      }

      const newHeader = btoa(JSON.stringify(decodedHeader)).replace(/=/g, '');
      const newBody = btoa(JSON.stringify(decodedBody)).replace(/=/g, '');
      
      return `${newHeader}.${newBody}.${signature}`;
    } catch (error) {
      console.error('Error modifying token:', error);
      return originalToken;
    }
  };

  const validateFuzzedToken = async (fuzzedToken, payload, category) => {
    try {
      const response = await fetch('http://localhost:8000/test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token: fuzzedToken })
      });

      const result = await response.json();
      return {
        token: fuzzedToken,
        originalPayload: payload,
        category,
        timestamp: new Date().toISOString(),
        validationResults: result.validation_results || [],
        success: result.success,
        error: result.error
      };
    } catch (error) {
      return {
        token: fuzzedToken,
        originalPayload: payload,
        category,
        timestamp: new Date().toISOString(),
        validationResults: [],
        success: false,
        error: error.message
      };
    }
  };

  const startFuzzing = async () => {
    if (!token) return;

    setIsRunning(true);
    setFuzzResults([]);
    const results = [];
    let completed = 0;
    let totalTests = 0;

    // Count total tests
    Object.entries(fuzzingPayloads).forEach(([category, payloads]) => {
      if (selectedPayloads[category]) {
        totalTests += payloads.length * 2; // Testing both header and payload locations
      }
    });

    // Run fuzzing tests
    for (const [category, payloads] of Object.entries(fuzzingPayloads)) {
      if (selectedPayloads[category]) {
        for (const payload of payloads) {
          // Test payload in header
          const headerFuzzedToken = modifyToken(token, { kid: payload }, 'header');
          const headerResult = await validateFuzzedToken(headerFuzzedToken, payload, category);
          results.push({ ...headerResult, location: 'header' });
          
          // Test payload in body
          const bodyFuzzedToken = modifyToken(token, payload, 'payload');
          const bodyResult = await validateFuzzedToken(bodyFuzzedToken, payload, category);
          results.push({ ...bodyResult, location: 'payload' });

          completed += 2;
          setProgress(Math.round((completed / totalTests) * 100));
        }
      }
    }

    setFuzzResults(results);
    setIsRunning(false);
    setProgress(0);

    // Log fuzzing session to audit log
    try {
      await fetch('http://localhost:8000/audit-log', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          action: 'Token Fuzzing',
          details: `Completed fuzzing session with ${results.length} tests`,
          severity: 'medium',
          success: true,
          token: token
        })
      });
    } catch (error) {
      console.error('Error logging fuzzing session:', error);
    }
  };

  const getSeverityBadge = (severity) => {
    const variant = severity === 'high' ? 'danger' :
                   severity === 'medium' ? 'warning' : 'info';
    return (
      <Badge bg={variant} className="me-2">
        {severity.toUpperCase()}
      </Badge>
    );
  };

  const getCategoryBadge = (category) => {
    const variants = {
      sql_injection: 'danger',
      path_traversal: 'warning',
      command_injection: 'danger',
      jwt_attacks: 'primary',
      null_byte: 'info'
    };

    return (
      <Badge bg={variants[category] || 'secondary'} className="me-2">
        {category.replace('_', ' ').toUpperCase()}
      </Badge>
    );
  };

  return (
    <div>
      <Card className="mb-4">
        <Card.Header>
          <h5 className="mb-0">Token Fuzzer</h5>
        </Card.Header>
        <Card.Body>
          <Form>
            <Form.Group className="mb-3">
              <Form.Label>Select Fuzzing Categories</Form.Label>
              <div>
                {Object.keys(fuzzingPayloads).map(category => (
                  <Form.Check
                    key={category}
                    type="checkbox"
                    id={`check-${category}`}
                    label={category.replace('_', ' ').toUpperCase()}
                    checked={selectedPayloads[category]}
                    onChange={(e) => setSelectedPayloads({
                      ...selectedPayloads,
                      [category]: e.target.checked
                    })}
                    inline
                  />
                ))}
              </div>
            </Form.Group>

            {isRunning && (
              <div className="mb-3">
                <div className="progress">
                  <div 
                    className="progress-bar progress-bar-striped progress-bar-animated"
                    role="progressbar"
                    style={{ width: `${progress}%` }}
                    aria-valuenow={progress}
                    aria-valuemin="0"
                    aria-valuemax="100"
                  >
                    {progress}%
                  </div>
                </div>
              </div>
            )}

            <Button 
              variant="primary" 
              onClick={startFuzzing}
              disabled={!token || isRunning}
            >
              {isRunning ? 'Fuzzing in Progress...' : 'Start Fuzzing'}
            </Button>
          </Form>

          {fuzzResults.length > 0 && (
            <div className="mt-4">
              <h6>Fuzzing Results</h6>
              <ListGroup>
                {fuzzResults.map((result, index) => (
                  <ListGroup.Item key={index}>
                    <Row>
                      <Col md={12}>
                        <div className="d-flex justify-content-between align-items-start mb-2">
                          <div>
                            {getCategoryBadge(result.category)}
                            <Badge bg={result.success ? 'success' : 'danger'} className="me-2">
                              {result.success ? 'PASS' : 'FAIL'}
                            </Badge>
                            <Badge bg="secondary">
                              {result.location.toUpperCase()}
                            </Badge>
                          </div>
                          <small className="text-muted">
                            {new Date(result.timestamp).toLocaleString()}
                          </small>
                        </div>
                        
                        <div className="mb-2">
                          <strong>Payload: </strong>
                          <code>{result.originalPayload}</code>
                        </div>

                        {result.validationResults.length > 0 && (
                          <div className="mb-2">
                            <strong>Validation Issues:</strong>
                            <ul className="mb-0">
                              {result.validationResults.map((validation, idx) => (
                                <li key={idx}>
                                  {getSeverityBadge(validation.severity)}
                                  {validation.description}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {result.error && (
                          <Alert variant="danger" className="mb-0 mt-2">
                            {result.error}
                          </Alert>
                        )}
                      </Col>
                    </Row>
                  </ListGroup.Item>
                ))}
              </ListGroup>
            </div>
          )}
        </Card.Body>
      </Card>
    </div>
  );
};

export default TokenFuzzer;