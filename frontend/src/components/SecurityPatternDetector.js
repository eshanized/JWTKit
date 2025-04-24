import React, { useEffect, useState } from 'react';
import { Card, ListGroup, Badge } from 'react-bootstrap';

const SecurityPatternDetector = ({ logs }) => {
  const [patterns, setPatterns] = useState([]);

  useEffect(() => {
    analyzePatterns();
  }, [logs]);

  const analyzePatterns = () => {
    const detectedPatterns = [];
    
    // Check for brute force attempts
    const recentLogs = logs.filter(log => {
      const logTime = new Date(log.timestamp).getTime();
      const fiveMinutesAgo = new Date().getTime() - (5 * 60 * 1000);
      return logTime > fiveMinutesAgo;
    });

    const ipCounts = {};
    recentLogs.forEach(log => {
      ipCounts[log.ip_address] = (ipCounts[log.ip_address] || 0) + 1;
    });

    Object.entries(ipCounts).forEach(([ip, count]) => {
      if (count > 50) {
        detectedPatterns.push({
          type: 'Brute Force',
          severity: 'high',
          details: `Potential brute force attack detected from IP ${ip} (${count} attempts in 5 minutes)`
        });
      }
    });

    // Check for algorithm confusion attempts
    const algNoneAttempts = logs.filter(log => 
      log.token && 
      (log.token.includes('"alg":"none"') || log.token.includes('"alg":null'))
    );

    if (algNoneAttempts.length > 0) {
      detectedPatterns.push({
        type: 'Algorithm Confusion',
        severity: 'high',
        details: 'Attempts to exploit algorithm confusion detected'
      });
    }

    // Check for signature stripping
    const strippedSigs = logs.filter(log =>
      log.token && log.token.split('.').length < 3
    );

    if (strippedSigs.length > 0) {
      detectedPatterns.push({
        type: 'Signature Stripping',
        severity: 'high',
        details: 'Attempts to remove token signatures detected'
      });
    }

    // Detect payload tampering patterns
    const commonPayloadAttacks = logs.filter(log =>
      log.token && (
        log.token.includes('"admin":true') ||
        log.token.includes('"role":"admin"') ||
        log.token.includes('"priv":') ||
        log.token.includes('"group":')
      )
    );

    if (commonPayloadAttacks.length > 0) {
      detectedPatterns.push({
        type: 'Payload Tampering',
        severity: 'high',
        details: 'Potential privilege escalation attempts detected in token payloads'
      });
    }

    setPatterns(detectedPatterns);
  };

  const getSeverityBadge = (severity) => {
    const variant = severity === 'high' ? 'danger' :
                   severity === 'medium' ? 'warning' : 'info';
    return <Badge bg={variant}>{severity.toUpperCase()}</Badge>;
  };

  return (
    <Card>
      <Card.Header>
        <h5 className="mb-0">Security Pattern Analysis</h5>
      </Card.Header>
      <Card.Body>
        {patterns.length === 0 ? (
          <p className="text-muted">No suspicious patterns detected</p>
        ) : (
          <ListGroup>
            {patterns.map((pattern, index) => (
              <ListGroup.Item key={index} className="d-flex justify-content-between align-items-start">
                <div className="ms-2 me-auto">
                  <div className="fw-bold">{pattern.type}</div>
                  {pattern.details}
                </div>
                {getSeverityBadge(pattern.severity)}
              </ListGroup.Item>
            ))}
          </ListGroup>
        )}
      </Card.Body>
    </Card>
  );
};

export default SecurityPatternDetector;