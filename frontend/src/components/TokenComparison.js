import React, { useState, useEffect } from 'react';
import { Card, Table, Badge, Button, Row, Col } from 'react-bootstrap';
import { diffChars } from 'diff';

const TokenComparison = ({ tokens }) => {
  const [decodedTokens, setDecodedTokens] = useState([]);
  const [differences, setDifferences] = useState({});
  const [securityAnalysis, setSecurityAnalysis] = useState([]);

  useEffect(() => {
    if (tokens && tokens.length > 0) {
      decodeTokens();
    }
  }, [tokens]);

  const decodeTokens = () => {
    const decoded = tokens.map(token => {
      try {
        const [header, payload, signature] = token.split('.');
        return {
          token,
          header: JSON.parse(atob(header)),
          payload: JSON.parse(atob(payload)),
          signature: signature,
          error: null
        };
      } catch (error) {
        return {
          token,
          header: null,
          payload: null,
          signature: null,
          error: 'Invalid token format'
        };
      }
    });

    setDecodedTokens(decoded);
    analyzeDifferences(decoded);
    performSecurityAnalysis(decoded);
  };

  const analyzeDifferences = (decoded) => {
    if (decoded.length < 2) return;

    const diffs = {};
    const baseToken = decoded[0];

    decoded.slice(1).forEach((compareToken, index) => {
      const headerDiff = diffChars(
        JSON.stringify(baseToken.header, null, 2),
        JSON.stringify(compareToken.header, null, 2)
      );
      
      const payloadDiff = diffChars(
        JSON.stringify(baseToken.payload, null, 2),
        JSON.stringify(compareToken.payload, null, 2)
      );

      diffs[index + 1] = {
        header: headerDiff,
        payload: payloadDiff,
        signatureDiffers: baseToken.signature !== compareToken.signature
      };
    });

    setDifferences(diffs);
  };

  const performSecurityAnalysis = async (decoded) => {
    const analysis = [];

    for (const token of decoded) {
      try {
        const response = await fetch('http://localhost:8000/test', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ token: token.token })
        });

        const result = await response.json();
        analysis.push({
          token: token.token,
          validationResults: result.validation_results || []
        });
      } catch (error) {
        console.error('Error analyzing token:', error);
        analysis.push({
          token: token.token,
          validationResults: [{
            type: 'error',
            description: 'Failed to analyze token',
            severity: 'high'
          }]
        });
      }
    }

    setSecurityAnalysis(analysis);
  };

  const renderDiff = (diff) => {
    return diff.map((part, index) => {
      const color = part.added ? 'lightgreen' :
                   part.removed ? 'lightcoral' : 'transparent';
      return (
        <span key={index} style={{ backgroundColor: color }}>
          {part.value}
        </span>
      );
    });
  };

  const getSecurityImplications = (tokenA, tokenB) => {
    const implications = [];

    // Algorithm changes
    if (tokenA.header?.alg !== tokenB.header?.alg) {
      implications.push({
        severity: 'high',
        message: `Algorithm changed from ${tokenA.header?.alg} to ${tokenB.header?.alg}`
      });
    }

    // Key ID changes
    if (tokenA.header?.kid !== tokenB.header?.kid) {
      implications.push({
        severity: 'medium',
        message: 'Key identifier (kid) has been modified'
      });
    }

    // Expiration time changes
    if (tokenA.payload?.exp !== tokenB.payload?.exp) {
      implications.push({
        severity: 'medium',
        message: 'Token expiration time has been modified'
      });
    }

    // Role or permission changes
    ['role', 'permissions', 'scope', 'admin'].forEach(claim => {
      if (tokenA.payload?.[claim] !== tokenB.payload?.[claim]) {
        implications.push({
          severity: 'high',
          message: `${claim} claim has been modified`
        });
      }
    });

    return implications;
  };

  const renderSecurityAnalysis = (tokenIndex) => {
    const analysis = securityAnalysis[tokenIndex];
    if (!analysis || !analysis.validationResults.length) return null;

    return (
      <div className="mt-3">
        <h6>Security Analysis</h6>
        <ul className="list-unstyled">
          {analysis.validationResults.map((result, idx) => (
            <li key={idx} className="mb-2">
              <Badge 
                bg={result.severity === 'high' ? 'danger' : 
                   result.severity === 'medium' ? 'warning' : 'info'}
                className="me-2"
              >
                {result.severity.toUpperCase()}
              </Badge>
              {result.description}
            </li>
          ))}
        </ul>
      </div>
    );
  };

  return (
    <Card>
      <Card.Header>
        <h5 className="mb-0">Token Comparison Analysis</h5>
      </Card.Header>
      <Card.Body>
        <div className="table-responsive">
          <Table bordered>
            <thead>
              <tr>
                <th>Component</th>
                {decodedTokens.map((_, index) => (
                  <th key={index}>Token {index + 1}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Header</td>
                {decodedTokens.map((token, index) => (
                  <td key={index}>
                    <pre className="mb-0">
                      {index === 0 ? (
                        JSON.stringify(token.header, null, 2)
                      ) : (
                        renderDiff(differences[index]?.header || [])
                      )}
                    </pre>
                    {renderSecurityAnalysis(index)}
                  </td>
                ))}
              </tr>
              <tr>
                <td>Payload</td>
                {decodedTokens.map((token, index) => (
                  <td key={index}>
                    <pre className="mb-0">
                      {index === 0 ? (
                        JSON.stringify(token.payload, null, 2)
                      ) : (
                        renderDiff(differences[index]?.payload || [])
                      )}
                    </pre>
                  </td>
                ))}
              </tr>
              <tr>
                <td>Signature</td>
                {decodedTokens.map((token, index) => (
                  <td key={index}>
                    <code className={
                      index > 0 && differences[index]?.signatureDiffers
                        ? 'text-danger'
                        : ''
                    }>
                      {token.signature}
                    </code>
                    {differences[index]?.signatureDiffers && (
                      <div className="mt-2">
                        <Badge bg="danger">Signature Mismatch</Badge>
                      </div>
                    )}
                  </td>
                ))}
              </tr>
            </tbody>
          </Table>
        </div>

        {Object.entries(differences).map(([index, diff]) => {
          const implications = getSecurityImplications(
            decodedTokens[0],
            decodedTokens[index]
          );

          if (implications.length === 0) return null;

          return (
            <Card key={index} className="mt-3">
              <Card.Header>
                <h6 className="mb-0">
                  Security Implications: Token 1 vs Token {parseInt(index) + 1}
                </h6>
              </Card.Header>
              <Card.Body>
                <ul className="list-unstyled">
                  {implications.map((implication, i) => (
                    <li key={i} className="mb-2">
                      <Badge 
                        bg={implication.severity === 'high' ? 'danger' : 'warning'}
                        className="me-2"
                      >
                        {implication.severity.toUpperCase()}
                      </Badge>
                      {implication.message}
                    </li>
                  ))}
                </ul>
              </Card.Body>
            </Card>
          );
        })}
      </Card.Body>
    </Card>
  );
};

export default TokenComparison;