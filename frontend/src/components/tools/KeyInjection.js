import React, { useState } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { toast } from 'react-toastify';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { 
  Container, Typography, TextField, Button, 
  Box, Paper, Grid, CircularProgress,
  Alert, AlertTitle, Divider, Chip, Switch,
  FormControlLabel, Tabs, Tab
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import SendIcon from '@mui/icons-material/Send';
import WarningIcon from '@mui/icons-material/Warning';
import KeyIcon from '@mui/icons-material/Key';
import ExtensionIcon from '@mui/icons-material/Extension';
import ReactJson from 'react-json-view';

const KeyInjection = () => {
  const [token, setToken] = useState('');
  const [kidValue, setKidValue] = useState('');
  const [jwkValue, setJwkValue] = useState('');
  const [useJwks, setUseJwks] = useState(false);
  const [jwksUrl, setJwksUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [attackTab, setAttackTab] = useState(0);
  
  const handleTokenChange = (e) => {
    setToken(e.target.value);
  };
  
  const handleKidChange = (e) => {
    setKidValue(e.target.value);
  };
  
  const handleJwkChange = (e) => {
    setJwkValue(e.target.value);
  };
  
  const handleJwksUrlChange = (e) => {
    setJwksUrl(e.target.value);
  };
  
  const handleAttackTabChange = (event, newValue) => {
    setAttackTab(newValue);
  };
  
  const executeAttack = async () => {
    if (!token) {
      toast.error('Please provide a JWT token');
      return;
    }
    
    if (attackTab === 0 && !kidValue) {
      toast.error('Please provide a Key ID (kid) value');
      return;
    }
    
    if (attackTab === 1 && !jwkValue) {
      toast.error('Please provide a JWK value');
      return;
    }
    
    if (attackTab === 2 && !jwksUrl) {
      toast.error('Please provide a JWKS URL');
      return;
    }
    
    try {
      setLoading(true);
      
      let payload;
      let endpoint = '/key-injection';
      
      switch (attackTab) {
        case 0: // KID Injection
          payload = {
            token,
            kid: kidValue,
            attack_type: 'kid_injection'
          };
          break;
        case 1: // JWK Injection
          payload = {
            token,
            jwk: JSON.parse(jwkValue),
            attack_type: 'jwk_injection'
          };
          break;
        case 2: // JWKS URL Spoofing
          payload = {
            token,
            jwks_url: jwksUrl,
            attack_type: 'jwks_url_spoofing'
          };
          endpoint = '/jwks-spoofing';
          break;
        default:
          payload = {
            token,
            kid: kidValue,
            attack_type: 'kid_injection'
          };
      }
      
      const response = await axios.post(endpoint, payload);
      
      setResults(response.data);
      toast.success('Attack executed successfully!');
    } catch (error) {
      console.error('Error executing attack:', error);
      
      if (error.response) {
        toast.error(error.response.data.error || 'Server error');
      } else if (error.message.includes('JSON')) {
        toast.error('Invalid JSON format in JWK');
      } else {
        toast.error('Network error');
      }
    } finally {
      setLoading(false);
    }
  };
  
  const getAttackDescription = () => {
    switch (attackTab) {
      case 0:
        return (
          <>
            <Typography variant="body2" paragraph>
              The 'kid' (Key ID) parameter is used in JWTs to indicate which key should be used for verification.
              This attack attempts to manipulate the 'kid' parameter to point to a file or location that the 
              attacker controls or can predict.
            </Typography>
            <Typography variant="body2" paragraph>
              Common injection patterns include:
            </Typography>
            <Box sx={{ pl: 2, mb: 2 }}>
              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                • kid: "/dev/null" (empty file)<br />
                • kid: "../../public/key.pem" (path traversal)<br />
                • kid: "mysql" (database connector)<br />
                • kid: "file:///etc/passwd" (file protocol)<br />
                • kid: "; exec('malicious code');" (code injection)
              </Typography>
            </Box>
          </>
        );
      case 1:
        return (
          <>
            <Typography variant="body2" paragraph>
              Some JWT libraries allow the inclusion of a JSON Web Key (JWK) directly within the token header.
              This attack attempts to inject a self-created JWK that would be used to verify the token instead
              of the server's key.
            </Typography>
            <Typography variant="body2" paragraph>
              Example of a JWK for a symmetric key:
            </Typography>
            <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 2, mb: 2 }}>
              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                {`{
  "kty": "oct",
  "k": "base64-encoded-secret",
  "alg": "HS256"
}`}
              </Typography>
            </Box>
          </>
        );
      case 2:
        return (
          <>
            <Typography variant="body2" paragraph>
              JWKS (JSON Web Key Set) URL spoofing occurs when an attacker can influence which URL is used to
              fetch the public keys for token verification. If the application fetches keys from a URL specified
              in the token, an attacker could point it to their own JWKS endpoint.
            </Typography>
            <Typography variant="body2" paragraph>
              This attack works when:
            </Typography>
            <Box sx={{ pl: 2, mb: 2 }}>
              <Typography variant="body2">
                • The application dynamically fetches JWKS from a URL specified in the token<br />
                • The token header contains a 'jku' (JWK Set URL) claim<br />
                • The application doesn't validate the JWKS URL against an allowlist
              </Typography>
            </Box>
          </>
        );
      default:
        return null;
    }
  };
  
  return (
    <Container maxWidth="lg">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Box sx={{ mb: 4, display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', mt: 2 }}>
            JWT Key Injection Attacks
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
            These attacks are designed to test vulnerabilities in JWT implementations. Use only on systems you have permission to test.
          </Typography>
        </Alert>
        
        <Grid container spacing={4}>
          <Grid item xs={12} md={6}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <KeyIcon color="primary" />
                Attack Configuration
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              <Box sx={{ width: '100%', mb: 3 }}>
                <Tabs
                  value={attackTab}
                  onChange={handleAttackTabChange}
                  variant="fullWidth"
                  aria-label="Key injection attack types"
                >
                  <Tab label="KID Injection" />
                  <Tab label="JWK Injection" />
                  <Tab label="JWKS URL Spoofing" />
                </Tabs>
              </Box>
              
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
              
              {attackTab === 0 && (
                <TextField
                  label="Key ID (kid) Value"
                  variant="outlined"
                  fullWidth
                  value={kidValue}
                  onChange={handleKidChange}
                  placeholder="e.g., '/dev/null', '../../../etc/passwd'"
                  sx={{ mb: 3 }}
                />
              )}
              
              {attackTab === 1 && (
                <TextField
                  label="JWK Value (JSON)"
                  variant="outlined"
                  fullWidth
                  multiline
                  rows={5}
                  value={jwkValue}
                  onChange={handleJwkChange}
                  placeholder='{"kty":"oct","k":"base64-encoded-secret","alg":"HS256"}'
                  sx={{ mb: 3 }}
                />
              )}
              
              {attackTab === 2 && (
                <TextField
                  label="JWKS URL"
                  variant="outlined"
                  fullWidth
                  value={jwksUrl}
                  onChange={handleJwksUrlChange}
                  placeholder="https://attacker.com/.well-known/jwks.json"
                  sx={{ mb: 3 }}
                />
              )}
              
              <Button
                variant="contained"
                color="primary"
                startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <SendIcon />}
                onClick={executeAttack}
                disabled={loading}
                fullWidth
                sx={{ mb: 3 }}
              >
                {loading ? 'Executing...' : 'Execute Attack'}
              </Button>
              
              <Box sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Attack Description
                </Typography>
                {getAttackDescription()}
              </Box>
            </Paper>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ExtensionIcon color="primary" />
                Results
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              {!results ? (
                <Box sx={{ py: 4, textAlign: 'center' }}>
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
                        <AlertTitle>Attack Successful!</AlertTitle>
                        <Typography variant="body2">
                          The system is vulnerable to {attackTab === 0 ? 'KID injection' : attackTab === 1 ? 'JWK injection' : 'JWKS URL spoofing'}.
                        </Typography>
                      </Alert>
                    ) : (
                      <Alert severity="success" sx={{ mb: 3 }}>
                        <AlertTitle>Attack Failed</AlertTitle>
                        <Typography variant="body2">
                          The system is not vulnerable to this attack vector.
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
                    
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="subtitle1" gutterBottom>
                        Full Response:
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
                    Mitigation Strategies
                  </Typography>
                  
                  {attackTab === 0 && (
                    <Alert severity="info" sx={{ mt: 2 }}>
                      <AlertTitle>How to prevent KID Injection</AlertTitle>
                      <ul>
                        <li>Validate and sanitize the 'kid' parameter before using it</li>
                        <li>Use a whitelist of allowed key identifiers</li>
                        <li>Store keys in a secure key store, not in the filesystem</li>
                        <li>Never use the 'kid' parameter directly as a file path</li>
                        <li>Implement proper input validation and character restrictions</li>
                      </ul>
                    </Alert>
                  )}
                  
                  {attackTab === 1 && (
                    <Alert severity="info" sx={{ mt: 2 }}>
                      <AlertTitle>How to prevent JWK Injection</AlertTitle>
                      <ul>
                        <li>Never trust keys embedded in the token itself</li>
                        <li>Disable the JWK header support if not needed</li>
                        <li>Always use pre-configured, trusted keys for verification</li>
                        <li>Implement strict token header validation</li>
                      </ul>
                    </Alert>
                  )}
                  
                  {attackTab === 2 && (
                    <Alert severity="info" sx={{ mt: 2 }}>
                      <AlertTitle>How to prevent JWKS URL Spoofing</AlertTitle>
                      <ul>
                        <li>Never trust a JWKS URL from the token</li>
                        <li>Maintain a whitelist of trusted JWKS endpoints</li>
                        <li>Always use pre-configured JWKS URLs</li>
                        <li>Implement certificate pinning for external JWKS endpoints</li>
                        <li>Validate the domains of any external URLs</li>
                      </ul>
                    </Alert>
                  )}
                </motion.div>
              )}
            </Paper>
          </Grid>
        </Grid>
      </motion.div>
    </Container>
  );
};

export default KeyInjection; 