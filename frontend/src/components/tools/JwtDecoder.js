import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { 
  Container, Paper, Typography, TextField, Button, 
  Box, Tabs, Tab, Grid, IconButton, Divider, 
  Alert, Chip, Tooltip
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import InfoIcon from '@mui/icons-material/Info';
import DeleteIcon from '@mui/icons-material/Delete';
import { toast } from 'react-toastify';
import ReactJson from 'react-json-view';
import axios from 'axios';

const JwtDecoder = () => {
  const [token, setToken] = useState('');
  const [decoded, setDecoded] = useState(null);
  const [selectedTab, setSelectedTab] = useState(0);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  
  // Effects for UI
  useEffect(() => {
    if (copied) {
      const timeout = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(timeout);
    }
  }, [copied]);
  
  const handleTokenChange = (e) => {
    const newToken = e.target.value;
    setToken(newToken);
    
    // Auto-decode if the token looks valid
    if (newToken.split('.').length === 3) {
      decodeToken(newToken);
    } else if (!newToken) {
      setDecoded(null);
    }
  };
  
  const decodeToken = async (tokenToDecode = token) => {
    try {
      setLoading(true);
      
      // First try to decode on the client side
      const parts = tokenToDecode.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }
      
      // Decode header and payload
      const decodeBase64 = (str) => {
        // Add padding if needed
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const padding = '='.repeat((4 - (base64.length % 4)) % 4);
        return JSON.parse(atob(base64 + padding));
      };
      
      const header = decodeBase64(parts[0]);
      const payload = decodeBase64(parts[1]);
      
      // Then also call the backend for full analysis
      const response = await axios.post('/decode', { token: tokenToDecode });
      
      setDecoded({ 
        header, 
        payload, 
        signature: parts[2],
        server_response: response.data 
      });
      
      setLoading(false);
    } catch (error) {
      console.error('Error decoding token:', error);
      setLoading(false);
      
      if (error.response) {
        // Backend error
        setDecoded({ error: error.response.data.error || 'Error from server' });
      } else {
        // Client-side error
        setDecoded({ error: error.message });
      }
    }
  };
  
  const clearToken = () => {
    setToken('');
    setDecoded(null);
  };
  
  const handleCopy = () => {
    setCopied(true);
    toast.success('Copied to clipboard!');
  };
  
  const handleTabChange = (event, newValue) => {
    setSelectedTab(newValue);
  };
  
  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A';
    
    try {
      const date = new Date(timestamp * 1000);
      return date.toLocaleString();
    } catch (e) {
      return 'Invalid date';
    }
  };
  
  const isExpired = (exp) => {
    if (!exp) return false;
    return exp * 1000 < Date.now();
  };
  
  const getLifetime = (iat, exp) => {
    if (!iat || !exp) return 'N/A';
    
    const durationSeconds = exp - iat;
    const hours = Math.floor(durationSeconds / 3600);
    const minutes = Math.floor((durationSeconds % 3600) / 60);
    
    return `${hours}h ${minutes}m`;
  };
  
  return (
    <Container maxWidth="lg">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 'bold', mt: 2 }}>
          JWT Decoder
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          Decode and analyze JWT tokens to inspect their contents and claims.
        </Typography>
        
        <Box sx={{ my: 4 }}>
          <TextField
            label="JWT Token"
            variant="outlined"
            fullWidth
            multiline
            rows={4}
            value={token}
            onChange={handleTokenChange}
            placeholder="Paste your JWT token here..."
            InputProps={{
              endAdornment: token && (
                <IconButton onClick={clearToken} edge="end">
                  <DeleteIcon />
                </IconButton>
              ),
            }}
          />
          
          <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
            <Button 
              variant="contained" 
              color="primary" 
              onClick={() => decodeToken()}
              disabled={!token || loading}
            >
              {loading ? 'Decoding...' : 'Decode Token'}
            </Button>
            
            <CopyToClipboard text={token} onCopy={handleCopy}>
              <Button 
                variant="outlined" 
                color="primary"
                startIcon={copied ? <CheckCircleIcon /> : <ContentCopyIcon />}
                disabled={!token}
              >
                {copied ? 'Copied!' : 'Copy Token'}
              </Button>
            </CopyToClipboard>
          </Box>
        </Box>
        
        {decoded && !decoded.error && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.2 }}
          >
            <Paper elevation={0} sx={{ p: 0, borderRadius: 2, overflow: 'hidden', mb: 4 }}>
              <Tabs
                value={selectedTab}
                onChange={handleTabChange}
                variant="fullWidth"
                sx={{ borderBottom: 1, borderColor: 'divider' }}
              >
                <Tab label="Decoded" />
                <Tab label="Header" />
                <Tab label="Payload" />
                <Tab label="Signature" />
              </Tabs>
              
              {/* Token Visual Representation */}
              {selectedTab === 0 && (
                <Box sx={{ p: 3 }}>
                  <Box className="jwt-token-display">
                    <CopyToClipboard text={token.split('.')[0]} onCopy={() => toast.success('Header copied!')}>
                      <Tooltip title="Copy Header">
                        <span className="jwt-token-header" style={{cursor: 'pointer'}}>{token.split('.')[0]}</span>
                      </Tooltip>
                    </CopyToClipboard>
                    <span className="jwt-token-dot">.</span>
                    <CopyToClipboard text={token.split('.')[1]} onCopy={() => toast.success('Payload copied!')}>
                      <Tooltip title="Copy Payload">
                        <span className="jwt-token-payload" style={{cursor: 'pointer'}}>{token.split('.')[1]}</span>
                      </Tooltip>
                    </CopyToClipboard>
                    <span className="jwt-token-dot">.</span>
                    <CopyToClipboard text={token.split('.')[2]} onCopy={() => toast.success('Signature copied!')}>
                      <Tooltip title="Copy Signature">
                        <span className="jwt-token-signature" style={{cursor: 'pointer'}}>{token.split('.')[2]}</span>
                      </Tooltip>
                    </CopyToClipboard>
                  </Box>
                  
                  <Typography variant="h6" gutterBottom sx={{ mt: 3, mb: 2 }}>
                    Token Information
                  </Typography>
                  
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                        <Typography variant="subtitle2" color="text.secondary">
                          Algorithm
                        </Typography>
                        <Typography variant="body1" sx={{ mt: 1 }}>
                          <Chip 
                            label={decoded.header.alg || 'None'} 
                            color={decoded.header.alg === 'none' ? 'error' : 'default'} 
                            size="small" 
                          />
                        </Typography>
                      </Paper>
                    </Grid>
                    
                    <Grid item xs={12} md={6}>
                      <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                        <Typography variant="subtitle2" color="text.secondary">
                          Token Type
                        </Typography>
                        <Typography variant="body1" sx={{ mt: 1 }}>
                          <Chip label={decoded.header.typ || 'Not specified'} size="small" />
                        </Typography>
                      </Paper>
                    </Grid>
                    
                    {decoded.payload.exp && (
                      <Grid item xs={12} md={6}>
                        <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                          <Typography variant="subtitle2" color="text.secondary" sx={{ display: 'flex', alignItems: 'center' }}>
                            <AccessTimeIcon fontSize="small" sx={{ mr: 1 }} />
                            Expiration
                          </Typography>
                          <Box sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography variant="body1">
                              {formatDate(decoded.payload.exp)}
                            </Typography>
                            {isExpired(decoded.payload.exp) ? (
                              <Chip 
                                label="Expired" 
                                color="error" 
                                size="small" 
                                icon={<ErrorIcon />} 
                              />
                            ) : (
                              <Chip 
                                label="Valid" 
                                color="success" 
                                size="small" 
                                icon={<CheckCircleIcon />} 
                              />
                            )}
                          </Box>
                        </Paper>
                      </Grid>
                    )}
                    
                    {decoded.payload.iat && (
                      <Grid item xs={12} md={6}>
                        <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                          <Typography variant="subtitle2" color="text.secondary">
                            Issued At
                          </Typography>
                          <Typography variant="body1" sx={{ mt: 1 }}>
                            {formatDate(decoded.payload.iat)}
                          </Typography>
                        </Paper>
                      </Grid>
                    )}
                    
                    {decoded.payload.iss && (
                      <Grid item xs={12} md={6}>
                        <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                          <Typography variant="subtitle2" color="text.secondary">
                            Issuer
                          </Typography>
                          <Typography variant="body1" sx={{ mt: 1 }}>
                            {decoded.payload.iss}
                          </Typography>
                        </Paper>
                      </Grid>
                    )}
                    
                    {decoded.payload.sub && (
                      <Grid item xs={12} md={6}>
                        <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                          <Typography variant="subtitle2" color="text.secondary">
                            Subject
                          </Typography>
                          <Typography variant="body1" sx={{ mt: 1 }}>
                            {decoded.payload.sub}
                          </Typography>
                        </Paper>
                      </Grid>
                    )}
                    
                    {decoded.payload.iat && decoded.payload.exp && (
                      <Grid item xs={12} md={6}>
                        <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                          <Typography variant="subtitle2" color="text.secondary">
                            Token Lifetime
                          </Typography>
                          <Typography variant="body1" sx={{ mt: 1 }}>
                            {getLifetime(decoded.payload.iat, decoded.payload.exp)}
                          </Typography>
                        </Paper>
                      </Grid>
                    )}
                    
                    {decoded.header.kid && (
                      <Grid item xs={12} md={6}>
                        <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                          <Typography variant="subtitle2" color="text.secondary">
                            Key ID
                          </Typography>
                          <Typography variant="body1" sx={{ mt: 1 }}>
                            {decoded.header.kid}
                          </Typography>
                        </Paper>
                      </Grid>
                    )}
                  </Grid>
                  
                  {decoded.header.alg === 'none' && (
                    <Alert severity="error" sx={{ mt: 3 }}>
                      <Typography variant="subtitle2">
                        Security Warning: Algorithm 'none'
                      </Typography>
                      <Typography variant="body2">
                        This token uses the 'none' algorithm, which means no signature verification 
                        is performed. This is a severe security issue and should never be used in production.
                      </Typography>
                    </Alert>
                  )}
                  
                  {!decoded.payload.exp && (
                    <Alert severity="warning" sx={{ mt: 3 }}>
                      <Typography variant="subtitle2">
                        No Expiration Claim
                      </Typography>
                      <Typography variant="body2">
                        This token does not contain an expiration time (exp claim).
                        Tokens without expiration are valid indefinitely, which is a security risk.
                      </Typography>
                    </Alert>
                  )}
                </Box>
              )}
              
              {/* Header Tab */}
              {selectedTab === 1 && (
                <Box sx={{ p: 3 }}>
                  <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="h6">Header Claims</Typography>
                    <CopyToClipboard text={JSON.stringify(decoded.header, null, 2)} onCopy={() => toast.success('Header copied!')}>
                      <Button startIcon={<ContentCopyIcon />} size="small">
                        Copy
                      </Button>
                    </CopyToClipboard>
                  </Box>
                  <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 2 }}>
                    <ReactJson 
                      src={decoded.header} 
                      theme={selectedTab === 'dark' ? 'monokai' : 'rjv-default'} 
                      name={false} 
                      displayDataTypes={false}
                      enableClipboard={false}
                      style={{ backgroundColor: 'transparent' }}
                    />
                  </Box>
                </Box>
              )}
              
              {/* Payload Tab */}
              {selectedTab === 2 && (
                <Box sx={{ p: 3 }}>
                  <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="h6">Payload Claims</Typography>
                    <CopyToClipboard text={JSON.stringify(decoded.payload, null, 2)} onCopy={() => toast.success('Payload copied!')}>
                      <Button startIcon={<ContentCopyIcon />} size="small">
                        Copy
                      </Button>
                    </CopyToClipboard>
                  </Box>
                  <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 2 }}>
                    <ReactJson 
                      src={decoded.payload} 
                      theme={selectedTab === 'dark' ? 'monokai' : 'rjv-default'} 
                      name={false} 
                      displayDataTypes={false}
                      enableClipboard={false}
                      style={{ backgroundColor: 'transparent' }}
                    />
                  </Box>
                </Box>
              )}
              
              {/* Signature Tab */}
              {selectedTab === 3 && (
                <Box sx={{ p: 3 }}>
                  <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="h6">Signature</Typography>
                    <CopyToClipboard text={decoded.signature} onCopy={() => toast.success('Signature copied!')}>
                      <Button startIcon={<ContentCopyIcon />} size="small">
                        Copy
                      </Button>
                    </CopyToClipboard>
                  </Box>
                  <Paper elevation={0} sx={{ p: 3, bgcolor: 'background.default', borderRadius: 2, wordBreak: 'break-all' }}>
                    <Typography variant="body2" component="div" fontFamily="monospace">
                      {decoded.signature === '' 
                        ? <Box sx={{ color: 'error.main' }}>No signature (empty string)</Box> 
                        : decoded.signature}
                    </Typography>
                  </Paper>
                  <Alert icon={<InfoIcon />} severity="info" sx={{ mt: 3 }}>
                    The signature is used to verify that the sender of the JWT is who it says it is and to ensure the message wasn't changed along the way.
                  </Alert>
                </Box>
              )}
            </Paper>
          </motion.div>
        )}
        
        {decoded && decoded.error && (
          <Alert severity="error" sx={{ mt: 3 }}>
            <Typography variant="subtitle2">Error Decoding Token</Typography>
            <Typography variant="body2">{decoded.error}</Typography>
          </Alert>
        )}
      </motion.div>
    </Container>
  );
};

export default JwtDecoder; 