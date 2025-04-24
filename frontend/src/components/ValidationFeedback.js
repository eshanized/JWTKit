import React from 'react';
import { Alert, ListGroup, Badge } from 'react-bootstrap';

const ValidationFeedback = ({ validationResults }) => {
  if (!validationResults || validationResults.length === 0) {
    return null;
  }

  const getSeverityVariant = (severity) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'danger';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'secondary';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'fa-exclamation-triangle';
      case 'medium':
        return 'fa-exclamation-circle';
      case 'low':
        return 'fa-info-circle';
      default:
        return 'fa-circle';
    }
  };

  return (
    <div className="validation-feedback mt-3">
      <ListGroup>
        {validationResults.map((result, index) => (
          <ListGroup.Item
            key={index}
            className={`d-flex justify-content-between align-items-center validation-item-${result.severity}`}
          >
            <div className="d-flex align-items-center">
              <i className={`fas ${getSeverityIcon(result.severity)} me-2 text-${getSeverityVariant(result.severity)}`}></i>
              <span>{result.description}</span>
            </div>
            <Badge bg={getSeverityVariant(result.severity)}>
              {result.severity.toUpperCase()}
            </Badge>
          </ListGroup.Item>
        ))}
      </ListGroup>

      {validationResults.some(r => r.severity === 'high') && (
        <Alert variant="warning" className="mt-3">
          <i className="fas fa-shield-alt me-2"></i>
          High severity issues detected. Use caution when testing this token.
        </Alert>
      )}
    </div>
  );
};

export default ValidationFeedback;