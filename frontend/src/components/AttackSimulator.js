import React, { useState } from 'react';
import { Card, Form, Button, Alert, Tabs, Tab, Spinner, Container, Row, Col } from 'react-bootstrap';
import HeaderInjectionAttacks from './HeaderInjectionAttacks';
import TokenFuzzer from './TokenFuzzer';
import axios from 'axios';

const AttackSimulator = ({ token, addToast }) => {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('none');
  
  // Form states for each attack type
  const [publicKey, setPublicKey] = useState('');
  const [wordlist, setWordlist] = useState('');
  const [kidValue, setKidValue] = useState('../../../dev/null');
  const [url, setUrl] = useState('');
  const [method, setMethod] = useState('GET');

  const API_URL = 'http://localhost:8000';

  const logAttackAttempt = async (action, details, severity, success, token) => {
    try {
      await axios.post('http://localhost:8000/audit-log', {
        action,
        details,
        severity,
        success,
        token
      });
    } catch (err) {
      console.error('Failed to log attack attempt:', err);
    }
  };

  const executeAttack = async (attackType, payload) => {
    setLoading(true);
    setError(null);
    setResult(null);

    const endpoints = {
      'none_algorithm_attack': '/attacks/none_algorithm',
      'algorithm_confusion_attack': '/attacks/algorithm_confusion',
      'jwt_brute_force': '/attacks/brute_force',
      'kid_injection_attack': '/attacks/kid_injection',
      'jwks_spoofing': '/attacks/jwks_spoof',
      'token_expiration_bypass': '/attacks/expiration_bypass',
      'test_token_against_endpoint': '/attacks/test_endpoint'
    };

    try {
      const endpoint = endpoints[attackType] || attackType;
      const response = await axios.post(`http://localhost:8000${endpoint}`, payload);
      
      if (response.data.success) {
        addToast(
          'Attack Successful',
          `${attackType} attack was successful`,
          'success'
        );
      } else {
        addToast(
          'Attack Failed',
          response.data.error || 'Attack did not succeed',
          'warning'
        );
      }
      
      setResult(response.data);
      
      // Log the attack attempt
      await logAttackAttempt(
        attackType,
        response.data.message || 'Attack execution completed',
        'high',
        response.data.success,
        payload.token
      );
    } catch (err) {
      const errorMessage = err.response?.data?.error || err.message;
      setError(errorMessage);
      addToast('Error', errorMessage, 'danger');
      
      // Log the failed attempt
      await logAttackAttempt(
        attackType,
        `Attack failed: ${errorMessage}`,
        'high',
        false,
        payload.token
      );
    } finally {
      setLoading(false);
    }
  };

  const handleNoneAttack = (e) => {
    e.preventDefault();
    executeAttack('none_algorithm_attack', { token });
  };

  const handleAlgorithmConfusion = (e) => {
    e.preventDefault();
    executeAttack('algorithm_confusion_attack', { token, public_key: publicKey });
  };

  const handleBruteForce = (e) => {
    e.preventDefault();
    executeAttack('jwt_brute_force', { token, wordlist });
  };

  const handleKidInjection = (e) => {
    e.preventDefault();
    executeAttack('kid_injection_attack', { token, kid_value: kidValue });
  };

  const handleJwksSpoofing = (e) => {
    e.preventDefault();
    executeAttack('jwks_spoofing', { token });
  };

  const handleExpirationBypass = (e) => {
    e.preventDefault();
    executeAttack('token_expiration_bypass', { token });
  };

  const handleEndpointTest = (e) => {
    e.preventDefault();
    executeAttack('test_token_against_endpoint', { token, url, method });
  };

  const renderResultCard = () => {
    if (loading) {
      return (
        <div className="text-center my-4">
          <Spinner animation="border" variant="primary" />
          <p className="mt-2">Simulating attack...</p>
        </div>
      );
    }

    if (error) {
      return <Alert variant="danger" className="mt-3">{error}</Alert>;
    }

    if (result) {
      return (
        <Card className="mt-3">
          <Card.Header>Attack Result</Card.Header>
          <Card.Body>
            <pre className="result-json">{JSON.stringify(result, null, 2)}</pre>
          </Card.Body>
        </Card>
      );
    }

    return null;
  };

  return (
    <Container>
      <h2 className="mb-4">JWT Attack Simulator</h2>
      {!token && (
        <Alert variant="warning">
          Please enter a JWT token first to use the attack simulator.
        </Alert>
      )}
      
      {token && (
        <>
          <p>Current token: <code className="token-display">{token}</code></p>
          
          <Tabs
            activeKey={activeTab}
            onSelect={(k) => setActiveTab(k)}
            className="mb-3"
          >
            <Tab eventKey="none" title="None Algorithm">
              <Card>
                <Card.Body>
                  <p>This attack modifies the token's header to use the 'none' algorithm, attempting to bypass signature verification.</p>
                  <Button 
                    variant="primary" 
                    onClick={handleNoneAttack}
                    disabled={loading}
                  >
                    Run None Algorithm Attack
                  </Button>
                </Card.Body>
              </Card>
            </Tab>
            
            <Tab eventKey="confusion" title="Algorithm Confusion">
              <Card>
                <Card.Body>
                  <p>This attack exploits implementations that verify RS256 signatures but use the public key for HS256 validation.</p>
                  <Form onSubmit={handleAlgorithmConfusion}>
                    <Form.Group className="mb-3">
                      <Form.Label>Public Key (PEM format)</Form.Label>
                      <Form.Control
                        as="textarea"
                        rows={5}
                        value={publicKey}
                        onChange={(e) => setPublicKey(e.target.value)}
                        placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
                        required
                      />
                    </Form.Group>
                    <Button 
                      type="submit" 
                      variant="primary"
                      disabled={loading}
                    >
                      Run Algorithm Confusion Attack
                    </Button>
                  </Form>
                </Card.Body>
              </Card>
            </Tab>
            
            <Tab eventKey="bruteforce" title="Brute Force">
              <Card>
                <Card.Body>
                  <p>This attack attempts to crack the token's secret key using a wordlist.</p>
                  <Form onSubmit={handleBruteForce}>
                    <Form.Group className="mb-3">
                      <Form.Label>Wordlist (one password per line)</Form.Label>
                      <Form.Control
                        as="textarea"
                        rows={5}
                        value={wordlist}
                        onChange={(e) => setWordlist(e.target.value)}
                        placeholder="password1&#10;password2&#10;password3"
                        required
                      />
                    </Form.Group>
                    <Button 
                      type="submit" 
                      variant="primary"
                      disabled={loading}
                    >
                      Run Brute Force Attack
                    </Button>
                  </Form>
                </Card.Body>
              </Card>
            </Tab>
            
            <Tab eventKey="kid" title="KID Injection">
              <Card>
                <Card.Body>
                  <p>This attack modifies the Key ID (kid) parameter to point to a file or resource controlled by the attacker.</p>
                  <Form onSubmit={handleKidInjection}>
                    <Form.Group className="mb-3">
                      <Form.Label>Injected KID Value</Form.Label>
                      <Form.Control
                        type="text"
                        value={kidValue}
                        onChange={(e) => setKidValue(e.target.value)}
                        placeholder="../../../dev/null"
                        required
                      />
                    </Form.Group>
                    <Button 
                      type="submit" 
                      variant="primary"
                      disabled={loading}
                    >
                      Run KID Injection Attack
                    </Button>
                  </Form>
                </Card.Body>
              </Card>
            </Tab>
            
            <Tab eventKey="jwks" title="JWKS Spoofing">
              <Card>
                <Card.Body>
                  <p>This attack generates a forged token with a spoofed JWKS (JSON Web Key Set) using attacker-controlled keys.</p>
                  <Button 
                    variant="primary" 
                    onClick={handleJwksSpoofing}
                    disabled={loading}
                  >
                    Run JWKS Spoofing Attack
                  </Button>
                </Card.Body>
              </Card>
            </Tab>
            
            <Tab eventKey="expiration" title="Expiration Bypass">
              <Card>
                <Card.Body>
                  <p>This attack attempts to bypass token expiration by removing or extending the 'exp' claim.</p>
                  <Button 
                    variant="primary" 
                    onClick={handleExpirationBypass}
                    disabled={loading}
                  >
                    Run Expiration Bypass Attack
                  </Button>
                </Card.Body>
              </Card>
            </Tab>
            
            <Tab eventKey="endpoint" title="Test Endpoint">
              <Card>
                <Card.Body>
                  <p>Test the token against a real endpoint to see if it's accepted.</p>
                  <Form onSubmit={handleEndpointTest}>
                    <Form.Group className="mb-3">
                      <Form.Label>Endpoint URL</Form.Label>
                      <Form.Control
                        type="url"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        placeholder="https://api.example.com/protected-resource"
                        required
                      />
                    </Form.Group>
                    <Form.Group className="mb-3">
                      <Form.Label>HTTP Method</Form.Label>
                      <Form.Select 
                        value={method}
                        onChange={(e) => setMethod(e.target.value)}
                      >
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                      </Form.Select>
                    </Form.Group>
                    <Button 
                      type="submit" 
                      variant="primary"
                      disabled={loading}
                    >
                      Test Endpoint
                    </Button>
                  </Form>
                </Card.Body>
              </Card>
            </Tab>

            <Tab eventKey="header_injection" title="Header Injection">
              <HeaderInjectionAttacks token={token} />
            </Tab>
            
            <Tab eventKey="fuzzer" title="Token Fuzzer">
              <TokenFuzzer token={token} />
            </Tab>
          </Tabs>
          
          {renderResultCard()}
        </>
      )}
      
      <Card className="mt-4 mb-4 bg-light">
        <Card.Body>
          <Card.Title className="text-danger">Disclaimer</Card.Title>
          <Card.Text>
            This tool is for educational purposes only. Only use these attack simulations against your own applications or 
            systems you have explicit permission to test. Unauthorized testing may violate laws and policies.
          </Card.Text>
        </Card.Body>
      </Card>
    </Container>
  );
};

export default AttackSimulator;