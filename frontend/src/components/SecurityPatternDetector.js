import React, { useState, useEffect } from 'react';
import { Card, Alert, ListGroup, Badge } from 'react-bootstrap';

const SecurityPatternDetector = ({ logs }) => {
  const [patterns, setPatterns] = useState([]);

  useEffect(() => {
    if (logs && logs.length > 0) {
      detectPatterns(logs);
    }
  }, [logs]);

  const detectPatterns = (logs) => {
    const detectedPatterns = [];
    const timeWindow = 5 * 60 * 1000; // 5 minutes in milliseconds
    
    // Group logs by IP address
    const ipGroups = {};
    logs.forEach(log => {
      if (!ipGroups[log.ip_address]) {
        ipGroups[log.ip_address] = [];
      }
      ipGroups[log.ip_address].push(log);
    });

    // Analyze patterns for each IP
    Object.entries(ipGroups).forEach(([ip, ipLogs]) => {
      // Sort logs by timestamp
      ipLogs.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

      // Check for rapid succession attacks
      const rapidAttacks = detectRapidAttacks(ipLogs, timeWindow);
      if (rapidAttacks) {
        detectedPatterns.push(rapidAttacks);
      }

      // Check for attack type progression
      const progression = detectAttackProgression(ipLogs);
      if (progression) {
        detectedPatterns.push(progression);
      }

      // Check for brute force patterns
      const bruteForce = detectBruteForcePattern(ipLogs);
      if (bruteForce) {
        detectedPatterns.push(bruteForce);
      }
    });

    setPatterns(detectedPatterns);
  };

  const detectRapidAttacks = (logs, timeWindow) => {
    const attacks = logs.filter(log => log.action.includes('Attack'));
    if (attacks.length >= 3) {
      const firstAttack = new Date(attacks[0].timestamp);
      const lastAttack = new Date(attacks[attacks.length - 1].timestamp);
      
      if (lastAttack - firstAttack <= timeWindow) {
        return {
          type: 'Rapid Succession Attacks',
          severity: 'high',
          details: `${attacks.length} attacks detected within ${timeWindow/1000/60} minutes from IP ${logs[0].ip_address}`,
          timestamp: new Date().toISOString()
        };
      }
    }
    return null;
  };

  const detectAttackProgression = (logs) => {
    const attackSequence = logs
      .filter(log => log.action.includes('Attack'))
      .map(log => log.action);
    
    if (attackSequence.length >= 3) {
      const uniqueAttacks = new Set(attackSequence).size;
      if (uniqueAttacks >= 3) {
        return {
          type: 'Attack Progression',
          severity: 'high',
          details: `Detected systematic progression through ${uniqueAttacks} different attack types`,
          timestamp: new Date().toISOString()
        };
      }
    }
    return null;
  };

  const detectBruteForcePattern = (logs) => {
    const bruteForceAttempts = logs.filter(log => 
      log.action.includes('Brute Force') || 
      log.details.toLowerCase().includes('brute force')
    );

    if (bruteForceAttempts.length >= 5) {
      return {
        type: 'Brute Force Campaign',
        severity: 'critical',
        details: `${bruteForceAttempts.length} brute force attempts detected`,
        timestamp: new Date().toISOString()
      };
    }
    return null;
  };

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'danger';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      default:
        return 'secondary';
    }
  };

  return (
    <Card>
      <Card.Header>
        <h5 className="mb-0">Security Pattern Analysis</h5>
      </Card.Header>
      <Card.Body>
        {patterns.length === 0 ? (
          <Alert variant="info">
            No suspicious patterns detected in the current logs.
          </Alert>
        ) : (
          <ListGroup>
            {patterns.map((pattern, index) => (
              <ListGroup.Item 
                key={index}
                className="d-flex justify-content-between align-items-center"
              >
                <div>
                  <h6 className="mb-1">
                    <Badge bg={getSeverityColor(pattern.severity)} className="me-2">
                      {pattern.severity.toUpperCase()}
                    </Badge>
                    {pattern.type}
                  </h6>
                  <p className="mb-0 text-muted small">
                    {pattern.details}
                  </p>
                  <small className="text-muted">
                    Detected at: {new Date(pattern.timestamp).toLocaleString()}
                  </small>
                </div>
              </ListGroup.Item>
            ))}
          </ListGroup>
        )}
      </Card.Body>
    </Card>
  );
};

export default SecurityPatternDetector;