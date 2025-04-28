import React, { useState } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { toast } from 'react-toastify';
import { 
  Container, Typography, TextField, Button, 
  Box, Paper, Grid, CircularProgress,
  Alert, AlertTitle, Divider, Chip, Accordion,
  AccordionSummary, AccordionDetails, Stepper,
  Step, StepLabel, LinearProgress
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import WarningIcon from '@mui/icons-material/Warning';
import SendIcon from '@mui/icons-material/Send';
import ReactJson from 'react-json-view';

const SecurityTester = () => {
  const [endpoint, setEndpoint] = useState('');
  const [authHeader, setAuthHeader] = useState('Authorization');
  const [additionalHeaders, setAdditionalHeaders] = useState('');
  const [activeStep, setActiveStep] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  
  const handleEndpointChange = (e) => {
    setEndpoint(e.target.value);
  };
  
  const handleAuthHeaderChange = (e) => {
    setAuthHeader(e.target.value);
  };
  
  const handleAdditionalHeadersChange = (e) => {
    setAdditionalHeaders(e.target.value);
  };
  
  const parseHeaders = () => {
    try {
      if (!additionalHeaders.trim()) {
        return {};
      }
      return JSON.parse(additionalHeaders);
    } catch (error) {
      toast.error('Invalid JSON format for additional headers');
      return {};
    }
  };
  
  const runSecurityScan = async () => {
    if (!endpoint) {
      toast.error('Please provide an endpoint URL');
      return;
    }
    
    try {
      setLoading(true);
      setActiveStep(0);
      setScanProgress(0);
      
      // Run scan with progress simulation
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 100) {
            clearInterval(progressInterval);
            return 100;
          }
          return prev + 5;
        });
        
        // Update step based on progress
        setActiveStep(prevStep => {
          const newProgress = scanProgress + 5;
          if (newProgress >= 90) return 3;
          if (newProgress >= 60) return 2;
          if (newProgress >= 30) return 1;
          return 0;
        });
      }, 500);
      
      const response = await axios.post('/security-scan', {
        endpoint,
        auth_header: authHeader,
        additional_headers: parseHeaders()
      });
      
      clearInterval(progressInterval);
      setScanProgress(100);
      setActiveStep(3);
      setResults(response.data);
      
      toast.success('Security scan completed!');
    } catch (error) {
      console.error('Error during security scan:', error);
      
      if (error.response) {
        toast.error(error.response.data.error || 'Server error');
      } else {
        toast.error('Network error');
      }
    } finally {
      setLoading(false);
    }
  };
  
  const getVulnerabilityCount = () => {
    if (!results || !results.vulnerabilities) return 0;
    return results.vulnerabilities.filter(v => v.severity === 'high').length;
  };
  
  const getWarningCount = () => {
    if (!results || !results.vulnerabilities) return 0;
    return results.vulnerabilities.filter(v => v.severity === 'medium').length;
  };
  
  const getInfoCount = () => {
    if (!results || !results.vulnerabilities) return 0;
    return results.vulnerabilities.filter(v => v.severity === 'low').length;
  };
  
  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'high':
        return <ErrorIcon color="error" />;
      case 'medium':
        return <WarningIcon color="warning" />;
      case 'low':
        return <InfoIcon color="info" />;
      default:
        return <InfoIcon />;
    }
  };
  
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'default';
    }
  };
  
  const steps = [
    'Testing Endpoint Connectivity',
    'Scanning JWT Configuration',
    'Testing Vulnerabilities',
    'Generating Report'
  ];
  
  return (
    <Container maxWidth="lg">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Box sx={{ mb: 4, display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', mt: 2 }}>
            JWT Security Scanner
          </Typography>
          <Chip 
            icon={<SecurityIcon />} 
            label="SECURITY TOOL" 
            color="primary" 
            variant="outlined" 
          />
        </Box>
        
        <Alert severity="info" sx={{ mb: 4 }}>
          <AlertTitle>Automated Security Testing</AlertTitle>
          <Typography variant="body2">
            This tool performs comprehensive security testing on JWT implementations.
            It checks for common vulnerabilities, misconfigurations, and best practices.
          </Typography>
        </Alert>
        
        <Grid container spacing={4}>
          <Grid item xs={12} md={5}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <SecurityIcon color="primary" />
                Scan Configuration
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              <Box sx={{ mb: 3 }}>
                <TextField
                  label="API Endpoint URL"
                  variant="outlined"
                  fullWidth
                  value={endpoint}
                  onChange={handleEndpointChange}
                  placeholder="https://api.example.com/protected-endpoint"
                  sx={{ mb: 3 }}
                  required
                />
                
                <TextField
                  label="Authorization Header Name"
                  variant="outlined"
                  fullWidth
                  value={authHeader}
                  onChange={handleAuthHeaderChange}
                  placeholder="Authorization"
                  sx={{ mb: 3 }}
                />
                
                <TextField
                  label="Additional Headers (JSON)"
                  variant="outlined"
                  fullWidth
                  multiline
                  rows={4}
                  value={additionalHeaders}
                  onChange={handleAdditionalHeadersChange}
                  placeholder='{"Content-Type": "application/json", "Custom-Header": "value"}'
                  sx={{ mb: 3 }}
                />
                
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <SendIcon />}
                  onClick={runSecurityScan}
                  disabled={loading || !endpoint}
                  fullWidth
                >
                  {loading ? 'Scanning...' : 'Start Security Scan'}
                </Button>
              </Box>
              
              {loading && (
                <Box sx={{ width: '100%', mt: 4 }}>
                  <Stepper activeStep={activeStep} orientation="vertical">
                    {steps.map((label, index) => (
                      <Step key={label}>
                        <StepLabel>{label}</StepLabel>
                      </Step>
                    ))}
                  </Stepper>
                  <Box sx={{ mt: 3 }}>
                    <LinearProgress variant="determinate" value={scanProgress} />
                    <Typography variant="body2" sx={{ mt: 1, textAlign: 'center' }}>
                      {scanProgress}% Complete
                    </Typography>
                  </Box>
                </Box>
              )}
            </Paper>
          </Grid>
          
          <Grid item xs={12} md={7}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>
                Scan Results
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              {!results ? (
                <Box sx={{ py: 8, textAlign: 'center' }}>
                  <Typography variant="body1" color="text.secondary">
                    Run a security scan to see results here
                  </Typography>
                </Box>
              ) : (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.2 }}
                >
                  <Box sx={{ mb: 4 }}>
                    <Grid container spacing={2}>
                      <Grid item xs={4}>
                        <Paper 
                          elevation={0} 
                          sx={{ 
                            p: 2, 
                            textAlign: 'center', 
                            bgcolor: 'error.light',
                            color: 'error.contrastText',
                            borderRadius: 2
                          }}
                        >
                          <Typography variant="h4">{getVulnerabilityCount()}</Typography>
                          <Typography variant="body2">Vulnerabilities</Typography>
                        </Paper>
                      </Grid>
                      <Grid item xs={4}>
                        <Paper 
                          elevation={0} 
                          sx={{ 
                            p: 2, 
                            textAlign: 'center', 
                            bgcolor: 'warning.light',
                            color: 'warning.contrastText',
                            borderRadius: 2
                          }}
                        >
                          <Typography variant="h4">{getWarningCount()}</Typography>
                          <Typography variant="body2">Warnings</Typography>
                        </Paper>
                      </Grid>
                      <Grid item xs={4}>
                        <Paper 
                          elevation={0} 
                          sx={{ 
                            p: 2, 
                            textAlign: 'center', 
                            bgcolor: 'info.light',
                            color: 'info.contrastText',
                            borderRadius: 2
                          }}
                        >
                          <Typography variant="h4">{getInfoCount()}</Typography>
                          <Typography variant="body2">Info</Typography>
                        </Paper>
                      </Grid>
                    </Grid>
                  </Box>
                  
                  <Typography variant="h6" gutterBottom sx={{ mt: 4 }}>
                    Vulnerability Assessment
                  </Typography>
                  
                  {results.vulnerabilities && results.vulnerabilities.map((vuln, index) => (
                    <Accordion key={index} sx={{ mb: 2 }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                          {getSeverityIcon(vuln.severity)}
                          <Typography variant="subtitle1">
                            {vuln.title}
                          </Typography>
                          <Chip 
                            label={vuln.severity.toUpperCase()} 
                            color={getSeverityColor(vuln.severity)} 
                            size="small" 
                            sx={{ ml: 2 }}
                          />
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Typography variant="body2" paragraph>
                          {vuln.description}
                        </Typography>
                        
                        {vuln.evidence && (
                          <Box sx={{ mt: 2, p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                            <Typography variant="subtitle2" gutterBottom>
                              Evidence:
                            </Typography>
                            <Typography variant="body2" component="pre" sx={{ 
                              fontFamily: 'monospace', 
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-all'
                            }}>
                              {vuln.evidence}
                            </Typography>
                          </Box>
                        )}
                        
                        <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                          Recommendation:
                        </Typography>
                        <Typography variant="body2">
                          {vuln.recommendation}
                        </Typography>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                  
                  <Typography variant="h6" gutterBottom sx={{ mt: 4 }}>
                    JWT Configuration
                  </Typography>
                  
                  {results.jwt_configuration && (
                    <Box sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                      <ReactJson 
                        src={results.jwt_configuration} 
                        name={false} 
                        displayDataTypes={false}
                        collapsed={1}
                        style={{ backgroundColor: 'transparent' }}
                      />
                    </Box>
                  )}
                  
                  <Divider sx={{ my: 4 }} />
                  
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="subtitle1">
                      Overall Security Score:
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                        {results.security_score}/100
                      </Typography>
                      <Chip 
                        label={results.security_score >= 80 ? "GOOD" : results.security_score >= 50 ? "NEEDS IMPROVEMENT" : "POOR"} 
                        color={results.security_score >= 80 ? "success" : results.security_score >= 50 ? "warning" : "error"}
                      />
                    </Box>
                  </Box>
                  
                  <Box sx={{ mt: 4 }}>
                    <Alert severity={results.security_score >= 80 ? "success" : "warning"}>
                      <AlertTitle>Summary</AlertTitle>
                      <Typography variant="body2">
                        {results.summary}
                      </Typography>
                    </Alert>
                  </Box>
                </motion.div>
              )}
            </Paper>
          </Grid>
        </Grid>
      </motion.div>
    </Container>
  );
};

export default SecurityTester; 