import React, { useState } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { toast } from 'react-toastify';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { 
  Container, Typography, TextField, Button, 
  Box, Paper, Grid, CircularProgress,
  Alert, AlertTitle, Divider, Chip, Accordion,
  AccordionSummary, AccordionDetails
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import SendIcon from '@mui/icons-material/Send';
import WarningIcon from '@mui/icons-material/Warning';
import CloudIcon from '@mui/icons-material/Cloud';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ReactJson from 'react-json-view';

const JwksSpoofer = () => {
  const [token, setToken] = useState('');
  const [jwksEndpoint, setJwksEndpoint] = useState('');
  const [customJwks, setCustomJwks] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  
  const handleTokenChange = (e) => {
    setToken(e.target.value);
  };
  
  const handleJwksEndpointChange = (e) => {
    setJwksEndpoint(e.target.value);
  };
  
  const handleCustomJwksChange = (e) => {
    setCustomJwks(e.target.value);
  };
  
  const executeAttack = async () => {
    if (!token || !jwksEndpoint) {
      toast.error('Please provide both a token and a JWKS endpoint URL');
      return;
    }
    
    try {
      setLoading(true);
      
      const payload = {
        token,
        jwks_url: jwksEndpoint,
        custom_jwks: customJwks ? JSON.parse(customJwks) : undefined
      };
      
      const response = await axios.post('/jwks-spoofing', payload);
      
      setResults(response.data);
      toast.success('JWKS spoofing attack executed successfully!');
    } catch (error) {
      console.error('Error executing attack:', error);
      
      if (error.response) {
        toast.error(error.response.data.error || 'Server error');
      } else if (error.message.includes('JSON')) {
        toast.error('Invalid JSON format in custom JWKS');
      } else {
        toast.error('Network error');
      }
    } finally {
      setLoading(false);
    }
  };
  
  const defaultJwksExample = `{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key-id",
      "use": "sig",
      "n": "base64-encoded-modulus",
      "e": "AQAB",
      "alg": "RS256"
    }
  ]
}`;
  
  return (
    <Container maxWidth="lg">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Box sx={{ mb: 4, display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', mt: 2 }}>
            JWKS URL Spoofing Attack
          </Typography>
          <Chip 
            icon={<WarningIcon />} 
            label="OFFENSIVE TECHNIQUE" 
            color="error" 
            variant="outlined" 
          />
        </Box>
        
        <Alert severity="warning" sx={{ mb: 4 }}>
          <AlertTitle>Educational Use Only</AlertTitle>
          <Typography variant="body2">
            This simulates JWKS URL spoofing attacks to test the security of JWT implementations. Use only for educational purposes and on systems you have permission to test.
          </Typography>
        </Alert>
        
        <Grid container spacing={4}>
          <Grid item xs={12} md={6}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CloudIcon color="primary" />
                Attack Configuration
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              <Box sx={{ mb: 3 }}>
                <TextField
                  label="JWT Token"
                  variant="outlined"
                  fullWidth
                  multiline
                  rows={4}
                  value={token}
                  onChange={handleTokenChange}
                  placeholder="Paste your JWT token here"
                  sx={{ mb: 3 }}
                />
                
                <TextField
                  label="Malicious JWKS Endpoint URL"
                  variant="outlined"
                  fullWidth
                  value={jwksEndpoint}
                  onChange={handleJwksEndpointChange}
                  placeholder="https://attacker.com/.well-known/jwks.json"
                  sx={{ mb: 3 }}
                />
                
                <TextField
                  label="Custom JWKS Content (Optional JSON)"
                  variant="outlined"
                  fullWidth
                  multiline
                  rows={6}
                  value={customJwks}
                  onChange={handleCustomJwksChange}
                  placeholder={defaultJwksExample}
                  sx={{ mb: 3 }}
                />
                
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <SendIcon />}
                  onClick={executeAttack}
                  disabled={loading || !token || !jwksEndpoint}
                  fullWidth
                  sx={{ mb: 3 }}
                >
                  {loading ? 'Executing...' : 'Execute Attack'}
                </Button>
              </Box>
              
              <Accordion 
                elevation={0}
                sx={{ 
                  bgcolor: 'background.default',
                  '&:before': {
                    display: 'none',
                  },
                }}
              >
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle2">How JWKS URL Spoofing Works</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" paragraph>
                    JSON Web Key Set (JWKS) URL spoofing is an attack where an attacker manipulates a JWT to make the 
                    verifier fetch keys from an attacker-controlled JWKS endpoint.
                  </Typography>
                  
                  <Typography variant="body2" paragraph>
                    The attack works when:
                  </Typography>
                  
                  <ol>
                    <li>The JWT header contains a 'jku' (JWK Set URL) claim or similar claims like 'x5u'</li>
                    <li>The application fetches keys from this URL without proper validation</li>
                    <li>The attacker provides their own public key in a valid JWKS format</li>
                    <li>The token is signed with the corresponding private key</li>
                  </ol>
                  
                  <Typography variant="body2" sx={{ mt: 2 }}>
                    When successful, the application will trust keys from the attacker's server, allowing tokens
                    signed by the attacker to be verified as valid.
                  </Typography>
                </AccordionDetails>
              </Accordion>
            </Paper>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom>
                Results
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              {!results ? (
                <Box sx={{ py: 8, textAlign: 'center' }}>
                  <Typography variant="body1" color="text.secondary">
                    Execute the attack to see results here
                  </Typography>
                </Box>
              ) : (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.2 }}
                >
                  <Box sx={{ mb: 3 }}>
                    {results.success ? (
                      <Alert severity="error" sx={{ mb: 3 }}>
                        <AlertTitle>Vulnerable!</AlertTitle>
                        <Typography variant="body2">
                          The system is vulnerable to JWKS URL spoofing. The verification process accepts keys from untrusted sources.
                        </Typography>
                      </Alert>
                    ) : (
                      <Alert severity="success" sx={{ mb: 3 }}>
                        <AlertTitle>Not Vulnerable</AlertTitle>
                        <Typography variant="body2">
                          The system correctly validates JWKS endpoints before fetching keys.
                        </Typography>
                      </Alert>
                    )}
                    
                    {results.modified_token && (
                      <Box sx={{ mb: 3 }}>
                        <Typography variant="subtitle1" gutterBottom>
                          Modified Token:
                        </Typography>
                        <Paper 
                          elevation={0}
                          sx={{ 
                            p: 2, 
                            bgcolor: 'background.default', 
                            borderRadius: 2,
                            position: 'relative',
                            fontFamily: 'monospace',
                            fontSize: 14,
                            wordBreak: 'break-all'
                          }}
                        >
                          {results.modified_token}
                          <CopyToClipboard text={results.modified_token} onCopy={() => toast.success('Token copied!')}>
                            <Button 
                              size="small" 
                              startIcon={<ContentCopyIcon />}
                              sx={{ position: 'absolute', top: 8, right: 8 }}
                            >
                              Copy
                            </Button>
                          </CopyToClipboard>
                        </Paper>
                      </Box>
                    )}
                    
                    <Box sx={{ mt: 3 }}>
                      <Typography variant="subtitle1" gutterBottom>
                        Response Details:
                      </Typography>
                      <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 2 }}>
                        <ReactJson 
                          src={results} 
                          name={false} 
                          displayDataTypes={false}
                          enableClipboard={false}
                          style={{ backgroundColor: 'transparent' }}
                          collapsed={1}
                        />
                      </Box>
                    </Box>
                  </Box>
                  
                  <Divider sx={{ my: 3 }} />
                  
                  <Typography variant="h6" gutterBottom>
                    Security Recommendations
                  </Typography>
                  
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <AlertTitle>How to Prevent JWKS URL Spoofing</AlertTitle>
                    <ul>
                      <li>Never trust a JWKS URL embedded in the token itself</li>
                      <li>Use a whitelist of allowed JWKS endpoints</li>
                      <li>Configure JWKS URLs statically in the application</li>
                      <li>Validate JWKS URLs against an allowed domain list</li>
                      <li>Implement certificate pinning for your identity provider</li>
                      <li>Use direct key exchange when possible instead of JWKS endpoints</li>
                    </ul>
                  </Alert>
                </motion.div>
              )}
            </Paper>
          </Grid>
        </Grid>
      </motion.div>
    </Container>
  );
};

export default JwksSpoofer; 