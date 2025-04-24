import React from 'react';
import { Card, ListGroup, Badge, Alert } from 'react-bootstrap';

const SecurityPatternDetector = ({ logs }) => {
  const detectPatterns = () => {
    if (!logs || logs.length === 0) return [];

    const patterns = [];
    const ipAttempts = {};
    const tokenAttempts = {};
    const timeWindows = {};
    
    logs.forEach(log => {
      // Track IP-based attempts
      if (log.ip_address) {
        ipAttempts[log.ip_address] = ipAttempts[log.ip_address] || {
          count: 0,
          failures: 0,
          attacks: new Set()
        };
        ipAttempts[log.ip_address].count++;
        if (!log.success) {
          ipAttempts[log.ip_address].failures++;
        }
        if (log.action) {
          ipAttempts[log.ip_address].attacks.add(log.action);
        }
      }

      // Track token reuse and modifications
      if (log.token) {
        tokenAttempts[log.token] = tokenAttempts[log.token] || {
          count: 0,
          timestamps: []
        };
        tokenAttempts[log.token].count++;
        tokenAttempts[log.token].timestamps.push(new Date(log.timestamp));
      }

      // Track time-based patterns
      const timeWindow = Math.floor(new Date(log.timestamp).getTime() / 60000); // 1-minute windows
      timeWindows[timeWindow] = timeWindows[timeWindow] || {
        count: 0,
        uniqueIPs: new Set(),
        uniqueTokens: new Set()
      };
      timeWindows[timeWindow].count++;
      if (log.ip_address) timeWindows[timeWindow].uniqueIPs.add(log.ip_address);
      if (log.token) timeWindows[timeWindow].uniqueTokens.add(log.token);
    });

    // Analyze IP-based patterns
    Object.entries(ipAttempts).forEach(([ip, data]) => {
      if (data.failures > 5) {
        patterns.push({
          type: 'brute_force',
          severity: 'high',
          description: `Potential brute force attack detected from IP ${ip} (${data.failures} failed attempts)`
        });
      }

      if (data.attacks.size > 3) {
        patterns.push({
          type: 'attack_variety',
          severity: 'high',
          description: `Multiple attack types detected from IP ${ip} (${Array.from(data.attacks).join(', ')})`
        });
      }
    });

    // Analyze token patterns
    Object.entries(tokenAttempts).forEach(([token, data]) => {
      if (data.count > 10) {
        patterns.push({
          type: 'token_reuse',
          severity: 'medium',
          description: `High frequency token reuse detected (${data.count} times)`
        });
      }

      // Check for rapid token reuse
      if (data.timestamps.length > 1) {
        const sortedTimestamps = data.timestamps.sort();
        for (let i = 1; i < sortedTimestamps.length; i++) {
          const timeDiff = sortedTimestamps[i] - sortedTimestamps[i-1];
          if (timeDiff < 1000) { // Less than 1 second apart
            patterns.push({
              type: 'rapid_reuse',
              severity: 'high',
              description: 'Suspicious rapid token reuse detected (multiple uses within 1 second)'
            });
            break;
          }
        }
      }
    });

    // Analyze time-based patterns
    Object.entries(timeWindows).forEach(([window, data]) => {
      if (data.count > 50) { // More than 50 attempts per minute
        patterns.push({
          type: 'high_frequency',
          severity: 'high',
          description: `High frequency of attempts detected (${data.count} attempts in 1 minute)`
        });
      }

      if (data.uniqueTokens.size > 20) { // More than 20 unique tokens per minute
        patterns.push({
          type: 'token_variety',
          severity: 'high',
          description: `Unusual variety of tokens detected (${data.uniqueTokens.size} unique tokens in 1 minute)`
        });
      }
    });

    return patterns;
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

  const getPatternExplanation = (type) => {
    const explanations = {
      brute_force: 'Multiple failed attempts indicate a possible automated attack trying to guess or break token signatures.',
      attack_variety: 'Multiple different attack types from the same source suggest systematic probing of vulnerabilities.',
      token_reuse: 'Excessive reuse of the same token may indicate token theft or replay attacks.',
      rapid_reuse: 'Very rapid reuse of tokens is characteristic of automated attack tools.',
      high_frequency: 'High frequency of attempts suggests automated tools rather than human activity.',
      token_variety: 'Large number of unique tokens in a short time period indicates possible token manipulation attempts.'
    };

    return explanations[type] || 'Unknown pattern detected';
  };

  const patterns = detectPatterns();

  if (patterns.length === 0) {
    return (
      <Card>
        <Card.Header>
          <h5 className="mb-0">Security Pattern Analysis</h5>
        </Card.Header>
        <Card.Body>
          <Alert variant="success">
            No suspicious patterns detected in the current activity.
          </Alert>
        </Card.Body>
      </Card>
    );
  }

  return (
    <Card>
      <Card.Header>
        <h5 className="mb-0">Security Pattern Analysis</h5>
      </Card.Header>
      <Card.Body>
        <ListGroup>
          {patterns.map((pattern, index) => (
            <ListGroup.Item key={index}>
              <div className="d-flex justify-content-between align-items-start">
                <div className="ms-2 me-auto">
                  <div className="mb-1">
                    {getSeverityBadge(pattern.severity)}
                    <strong>{pattern.description}</strong>
                  </div>
                  <small className="text-muted">
                    {getPatternExplanation(pattern.type)}
                  </small>
                </div>
              </div>
            </ListGroup.Item>
          ))}
        </ListGroup>
      </Card.Body>
    </Card>
  );
};

export default SecurityPatternDetector;