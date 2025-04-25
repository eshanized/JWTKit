import React, { useState, useEffect } from 'react';
import { Box, Typography, List, ListItem, ListItemText, Paper, Alert } from '@mui/material';

const SecurityPatternDetector = ({ logs = [] }) => {
  const [detectedPatterns, setDetectedPatterns] = useState([]);
  const [patternDetails, setPatternDetails] = useState({});

  useEffect(() => {
    analyzePatterns();
  }, [logs]);

  const analyzePatterns = () => {
    const patterns = [];
    const details = {};

    // Skip analysis if logs is undefined or empty
    if (!logs || logs.length === 0) {
      setDetectedPatterns([]);
      setPatternDetails({});
      return;
    }

    // Check for brute force attempts
    const loginFailures = logs.filter(log => 
      log.action === 'login_failed'
    );
    
    // Group by IP and check if any IP has multiple failed attempts
    const ipAttempts = {};
    loginFailures.forEach(log => {
      const ip = log.ip_address;
      ipAttempts[ip] = (ipAttempts[ip] || 0) + 1;
    });
    
    const bruteForceIPs = Object.keys(ipAttempts).filter(ip => ipAttempts[ip] >= 5);
    
    if (bruteForceIPs.length > 0) {
      patterns.push('Brute Force Attempts');
      details['Brute Force Attempts'] = {
        description: 'Multiple failed login attempts from the same IP address',
        ips: bruteForceIPs,
        counts: bruteForceIPs.map(ip => ipAttempts[ip])
      };
    }

    // Check for algorithm confusion attempts
    const algConfusionAttempts = logs.filter(log => 
      log.action === 'token_verification_failed' && 
      log.details && 
      log.details.includes('algorithm confusion')
    );
    
    if (algConfusionAttempts.length > 0) {
      patterns.push('Algorithm Confusion');
      details['Algorithm Confusion'] = {
        description: 'Attempts to exploit algorithm confusion vulnerability',
        count: algConfusionAttempts.length,
        examples: algConfusionAttempts.slice(0, 3).map(log => log.details)
      };
    }

    // Check for signature stripping attempts
    const sigStripAttempts = logs.filter(log => 
      log.action === 'token_verification_failed' && 
      log.details && 
      log.details.includes('signature stripped')
    );
    
    if (sigStripAttempts.length > 0) {
      patterns.push('Signature Stripping');
      details['Signature Stripping'] = {
        description: 'Attempts to use tokens with removed signatures',
        count: sigStripAttempts.length,
        examples: sigStripAttempts.slice(0, 3).map(log => log.details)
      };
    }

    // Check for payload tampering
    const payloadTamperAttempts = logs.filter(log => 
      log.action === 'token_validation_failed' && 
      log.details && 
      log.details.includes('payload tampering')
    );
    
    if (payloadTamperAttempts.length > 0) {
      patterns.push('Payload Tampering');
      details['Payload Tampering'] = {
        description: 'Attempts to modify token payload data',
        count: payloadTamperAttempts.length,
        examples: payloadTamperAttempts.slice(0, 3).map(log => log.details)
      };
    }

    setDetectedPatterns(patterns);
    setPatternDetails(details);
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>Security Pattern Analysis</Typography>
      
      {!logs || logs.length === 0 ? (
        <Alert severity="info">No logs available for analysis</Alert>
      ) : detectedPatterns.length === 0 ? (
        <Alert severity="success">No suspicious patterns detected in logs</Alert>
      ) : (
        <>
          <Alert severity="warning">
            {detectedPatterns.length} suspicious pattern{detectedPatterns.length > 1 ? 's' : ''} detected
          </Alert>
          <List>
            {detectedPatterns.map(pattern => (
              <ListItem key={pattern} component={Paper} elevation={2} sx={{ mb: 2, p: 2 }}>
                <ListItemText
                  primary={pattern}
                  secondary={
                    <Box sx={{ mt: 1 }}>
                      <Typography variant="body2">{patternDetails[pattern]?.description}</Typography>
                      <Typography variant="body2" sx={{ mt: 1 }}>
                        Occurrences: {patternDetails[pattern]?.count || 
                                     (patternDetails[pattern]?.ips && patternDetails[pattern]?.ips.length)}
                      </Typography>
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>
        </>
      )}
    </Box>
  );
};

export default SecurityPatternDetector;