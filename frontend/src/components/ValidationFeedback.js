import React from 'react';
import { Card, ListGroup, Badge, ProgressBar } from 'react-bootstrap';

const ValidationFeedback = ({ token, validationResults }) => {
  const calculateSecurityScore = () => {
    if (!token || !validationResults) return 0;
    
    let score = 100;
    const penalties = {
      alg_none: 40,
      kid_sql: 30,
      kid_path_traversal: 30,
      admin_claim: 25,
      expired: 15,
      weak_algorithm: 20,
      missing_exp: 10,
      missing_iat: 5,
      missing_kid: 5
    };

    validationResults.forEach(result => {
      if (penalties[result.type]) {
        score -= penalties[result.type];
      }
    });

    return Math.max(0, score);
  };

  const getScoreVariant = (score) => {
    if (score >= 80) return 'success';
    if (score >= 60) return 'warning';
    return 'danger';
  };

  const getSecurityLevel = (score) => {
    if (score >= 80) return 'Strong';
    if (score >= 60) return 'Moderate';
    if (score >= 40) return 'Weak';
    return 'Critical';
  };

  const getRecommendations = () => {
    const recommendations = [];
    
    if (!token) {
      return ['No token provided for analysis'];
    }

    validationResults.forEach(result => {
      switch (result.type) {
        case 'alg_none':
          recommendations.push('Use a secure algorithm (HS256, RS256) instead of "none"');
          break;
        case 'kid_sql':
          recommendations.push('Sanitize and validate the kid header parameter');
          break;
        case 'kid_path_traversal':
          recommendations.push('Prevent path traversal in kid header by using secure key identifiers');
          break;
        case 'admin_claim':
          recommendations.push('Avoid using sensitive role claims directly in the token');
          break;
        case 'expired':
          recommendations.push('Token has expired. Generate a new token with appropriate expiration');
          break;
        case 'weak_algorithm':
          recommendations.push('Use a stronger signing algorithm (RS256 recommended)');
          break;
        case 'missing_exp':
          recommendations.push('Add expiration claim (exp) to limit token lifetime');
          break;
        case 'missing_iat':
          recommendations.push('Add issued at claim (iat) to track token creation time');
          break;
        case 'missing_kid':
          recommendations.push('Add key identifier (kid) for proper key management');
          break;
        default:
          break;
      }
    });

    return recommendations;
  };

  const securityScore = calculateSecurityScore();

  return (
    <Card>
      <Card.Header>
        <h5 className="mb-0">Security Analysis Feedback</h5>
      </Card.Header>
      <Card.Body>
        <div className="mb-4">
          <div className="d-flex justify-content-between align-items-center mb-2">
            <span>Security Score</span>
            <Badge bg={getScoreVariant(securityScore)}>
              {getSecurityLevel(securityScore)}
            </Badge>
          </div>
          <ProgressBar
            now={securityScore}
            variant={getScoreVariant(securityScore)}
            className="mb-2"
          />
          <small className="text-muted">
            Score: {securityScore}/100
          </small>
        </div>

        {validationResults && validationResults.length > 0 && (
          <>
            <h6>Detected Issues:</h6>
            <ListGroup className="mb-4">
              {validationResults.map((result, index) => (
                <ListGroup.Item
                  key={index}
                  className="d-flex justify-content-between align-items-start"
                >
                  <div className="ms-2 me-auto">
                    <div className="fw-bold">{result.type}</div>
                    {result.description}
                  </div>
                  <Badge 
                    bg={result.severity === 'high' ? 'danger' : 
                       result.severity === 'medium' ? 'warning' : 'info'}
                    pill
                  >
                    {result.severity}
                  </Badge>
                </ListGroup.Item>
              ))}
            </ListGroup>
          </>
        )}

        <h6>Recommendations:</h6>
        <ListGroup>
          {getRecommendations().map((recommendation, index) => (
            <ListGroup.Item key={index}>
              <i className="fas fa-check-circle text-success me-2"></i>
              {recommendation}
            </ListGroup.Item>
          ))}
        </ListGroup>
      </Card.Body>
    </Card>
  );
};

export default ValidationFeedback;