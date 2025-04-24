import React, { useState } from 'react';
import { Card, Button, Alert, Tabs, Tab, Form } from 'react-bootstrap';
import axios from 'axios';

const HeaderInjectionAttacks = ({ token }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [activeTab, setActiveTab] = useState('jwk');

  const handleJwkInjection = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post('http://localhost:8000/attacks/jwk_injection', {
        token
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleX5cInjection = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post('http://localhost:8000/attacks/x5c_injection', {
        token
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const renderResult = () => {
    if (!result) return null;

    return (
      <Card className="mt-3">
        <Card.Header className={result.success ? 'bg-success text-white' : 'bg-danger text-white'}>
          Attack Result
        </Card.Header>
        <Card.Body>
          {result.success ? (
            <>
              <Alert variant="success">
                <i className="bi bi-check-circle-fill me-2"></i>
                {result.message}
              </Alert>
              <div className="mt-3">
                <h6>Forged Token:</h6>
                <div className="border p-2 bg-light">
                  <code className="text-break">{result.forged_token}</code>
                </div>
              </div>
              {result.injected_jwk && (
                <div className="mt-3">
                  <h6>Injected JWK:</h6>
                  <pre className="border p-2 bg-light">
                    {JSON.stringify(result.injected_jwk, null, 2)}
                  </pre>
                </div>
              )}
              {result.injected_certificate && (
                <div className="mt-3">
                  <h6>Injected Certificate:</h6>
                  <pre className="border p-2 bg-light">
                    {result.injected_certificate}
                  </pre>
                </div>
              )}
            </>
          ) : (
            <Alert variant="danger">
              <i className="bi bi-x-circle-fill me-2"></i>
              Attack failed: {result.error}
            </Alert>
          )}
        </Card.Body>
      </Card>
    );
  };

  return (
    <div>
      <h5>Header Injection Attacks</h5>
      <Tabs activeKey={activeTab} onSelect={k => setActiveTab(k)} className="mb-3">
        <Tab eventKey="jwk" title="JWK Injection">
          <Card>
            <Card.Body>
              <p>
                This attack attempts to inject a forged JSON Web Key (JWK) into the token header. 
                The attack generates a new key pair and includes the public key in the header, 
                signed with the corresponding private key.
              </p>
              <Button
                variant="primary"
                onClick={handleJwkInjection}
                disabled={loading || !token}
              >
                {loading ? 'Running Attack...' : 'Run JWK Injection Attack'}
              </Button>
            </Card.Body>
          </Card>
        </Tab>
        <Tab eventKey="x5c" title="X.509 Certificate Injection">
          <Card>
            <Card.Body>
              <p>
                This attack attempts to inject a forged X.509 certificate chain into the token header.
                The attack generates a self-signed certificate and includes it in the x5c header parameter.
              </p>
              <Button
                variant="primary"
                onClick={handleX5cInjection}
                disabled={loading || !token}
              >
                {loading ? 'Running Attack...' : 'Run X.509 Certificate Injection Attack'}
              </Button>
            </Card.Body>
          </Card>
        </Tab>
      </Tabs>

      {error && (
        <Alert variant="danger" className="mt-3">
          {error}
        </Alert>
      )}

      {renderResult()}
    </div>
  );
};

export default HeaderInjectionAttacks;