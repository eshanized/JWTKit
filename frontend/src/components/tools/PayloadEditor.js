import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { toast } from 'react-toastify';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { 
  Container, Typography, TextField, Button, 
  Box, Paper, Grid, CircularProgress,
  Alert, Divider, Chip, FormControl,
  InputLabel, Select, MenuItem, Tabs, Tab
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import EditIcon from '@mui/icons-material/Edit';
import PublishIcon from '@mui/icons-material/Publish';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import ReactJson from 'react-json-view';

const PayloadEditor = () => {
  const [token, setToken] = useState('');
  const [secret, setSecret] = useState('');
  const [algorithm, setAlgorithm] = useState('HS256');
  const [decodedHeader, setDecodedHeader] = useState(null);
  const [decodedPayload, setDecodedPayload] = useState(null);
  const [editedHeader, setEditedHeader] = useState(null);
  const [editedPayload, setEditedPayload] = useState(null);
  const [loading, setLoading] = useState(false);
  const [modifiedToken, setModifiedToken] = useState('');
  const [copied, setCopied] = useState(false);
  const [currentTab, setCurrentTab] = useState(0);
  
  // Reset copy state after 2 seconds
  useEffect(() => {
    if (copied) {
      const timeout = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(timeout);
    }
  }, [copied]);
  
  const handleTokenChange = (e) => {
    setToken(e.target.value);
    
    // Auto-decode if the token looks valid
    if (e.target.value.split('.').length === 3) {
      decodeToken(e.target.value);
    } else {
      setDecodedHeader(null);
      setDecodedPayload(null);
      setEditedHeader(null);
      setEditedPayload(null);
    }
  };
  
  const handleSecretChange = (e) => {
    setSecret(e.target.value);
  };
  
  const handleAlgorithmChange = (e) => {
    setAlgorithm(e.target.value);
  };
  
  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
  };
  
  const decodeToken = (tokenToDecode = token) => {
    try {
      // Split the token
      const parts = tokenToDecode.split('.');
      if (parts.length !== 3) {
        toast.error('Invalid JWT format');
        return;
      }
      
      // Decode header and payload
      const decodeBase64 = (str) => {
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const padding = '='.repeat((4 - (base64.length % 4)) % 4);
        return JSON.parse(atob(base64 + padding));
      };
      
      const header = decodeBase64(parts[0]);
      const payload = decodeBase64(parts[1]);
      
      setDecodedHeader(header);
      setDecodedPayload(payload);
      setEditedHeader(header);
      setEditedPayload(payload);
    } catch (error) {
      console.error('Error decoding token:', error);
      toast.error('Error decoding JWT: ' + error.message);
    }
  };
  
  const handleHeaderUpdate = (data) => {
    setEditedHeader(data.updated_src);
  };
  
  const handlePayloadUpdate = (data) => {
    setEditedPayload(data.updated_src);
  };
  
  const generateToken = async () => {
    if (!editedPayload) {
      toast.error('Payload is required');
      return;
    }
    
    // For none algorithm, secret is optional
    if (algorithm !== 'none' && !secret) {
      toast.error('Secret is required for signing');
      return;
    }
    
    try {
      setLoading(true);
      
      const response = await axios.post('/modify', {
        token: token || undefined, // Send original token for reference if available
        new_payload: editedPayload,
        secret,
        algorithm
      });
      
      setModifiedToken(response.data.modified_token);
      toast.success('Token generated successfully!');
      setCurrentTab(2); // Switch to result tab
    } catch (error) {
      console.error('Error generating token:', error);
      
      if (error.response) {
        toast.error(error.response.data.error || 'Server error');
      } else {
        toast.error('Network error');
      }
    } finally {
      setLoading(false);
    }
  };
  
  const handleCopy = () => {
    setCopied(true);
    toast.success('Token copied to clipboard!');
  };
  
  const getAlgorithmHelp = (alg) => {
    const algInfo = {
      'HS256': 'HMAC with SHA-256 (symmetric)',
      'HS384': 'HMAC with SHA-384 (symmetric)',
      'HS512': 'HMAC with SHA-512 (symmetric)',
      'RS256': 'RSA with SHA-256 (asymmetric)',
      'RS384': 'RSA with SHA-384 (asymmetric)',
      'RS512': 'RSA with SHA-512 (asymmetric)',
      'ES256': 'ECDSA with SHA-256 (asymmetric)',
      'ES384': 'ECDSA with SHA-384 (asymmetric)',
      'ES512': 'ECDSA with SHA-512 (asymmetric)',
      'none': 'No signature verification (insecure)'
    }[alg];
    
    return algInfo || 'Unknown algorithm';
  };
  
  const secretHelp = () => {
    if (algorithm === 'none') {
      return 'No secret needed for "none" algorithm';
    }
    
    if (algorithm.startsWith('HS')) {
      return 'Provide the shared secret key for HMAC algorithms';
    }
    
    if (algorithm.startsWith('RS') || algorithm.startsWith('ES')) {
      return 'Provide the private key in PEM format for asymmetric algorithms';
    }
    
    return 'Provide a secret for signing';
  };
  
  // Available signing algorithms
  const algorithms = [
    'HS256', 'HS384', 'HS512',
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'none'
  ];
  
  return (
    <Container maxWidth="lg">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', mt: 2 }}>
            JWT Payload Editor
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mt: 1 }}>
            Decode, modify, and resign JWT tokens with custom claims and algorithms
          </Typography>
        </Box>
        
        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
          <Tabs 
            value={currentTab} 
            onChange={handleTabChange} 
            aria-label="jwt editor tabs"
            variant="fullWidth"
          >
            <Tab label="Decode & Edit" />
            <Tab label="Sign Token" />
            <Tab label="Result" disabled={!modifiedToken} />
          </Tabs>
        </Box>
        
        {/* Tab 1: Decode & Edit */}
        {currentTab === 0 && (
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Input Token
                </Typography>
                <TextField
                  label="JWT Token (optional)"
                  variant="outlined"
                  fullWidth
                  multiline
                  rows={3}
                  value={token}
                  onChange={handleTokenChange}
                  placeholder="Paste an existing JWT token or create a new one"
                  sx={{ mb: 2 }}
                />
                
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <Button 
                    variant="contained" 
                    onClick={() => decodeToken()}
                    disabled={!token || token.split('.').length !== 3}
                  >
                    Decode Token
                  </Button>
                  <Button 
                    variant="outlined"
                    onClick={() => {
                      setDecodedPayload({
                        sub: '123456789',
                        name: 'John Doe',
                        iat: Math.floor(Date.now() / 1000),
                        exp: Math.floor(Date.now() / 1000) + 3600
                      });
                      setDecodedHeader({ alg: 'HS256', typ: 'JWT' });
                      setEditedPayload({
                        sub: '123456789',
                        name: 'John Doe',
                        iat: Math.floor(Date.now() / 1000),
                        exp: Math.floor(Date.now() / 1000) + 3600
                      });
                      setEditedHeader({ alg: 'HS256', typ: 'JWT' });
                    }}
                  >
                    Create New
                  </Button>
                </Box>
              </Paper>
            </Grid>
            
            {(decodedHeader || decodedPayload) && (
              <>
                <Grid item xs={12} md={6}>
                  <Paper elevation={0} sx={{ p: 3, borderRadius: 2, height: '100%' }}>
                    <Typography variant="h6" gutterBottom>
                      Header
                    </Typography>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        The header specifies the algorithm used for signing the token.
                      </Typography>
                    </Alert>
                    {editedHeader && (
                      <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 2 }}>
                        <ReactJson 
                          src={editedHeader} 
                          onEdit={handleHeaderUpdate}
                          onAdd={handleHeaderUpdate}
                          onDelete={handleHeaderUpdate}
                          displayDataTypes={false}
                          name={false}
                          style={{ backgroundColor: 'transparent' }}
                        />
                      </Box>
                    )}
                  </Paper>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Paper elevation={0} sx={{ p: 3, borderRadius: 2, height: '100%' }}>
                    <Typography variant="h6" gutterBottom>
                      Payload
                    </Typography>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        The payload contains the claims and data stored in the token.
                      </Typography>
                    </Alert>
                    {editedPayload && (
                      <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 2 }}>
                        <ReactJson 
                          src={editedPayload} 
                          onEdit={handlePayloadUpdate}
                          onAdd={handlePayloadUpdate}
                          onDelete={handlePayloadUpdate}
                          displayDataTypes={false}
                          name={false}
                          style={{ backgroundColor: 'transparent' }}
                        />
                      </Box>
                    )}
                  </Paper>
                </Grid>
                
                <Grid item xs={12}>
                  <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
                    <Button 
                      variant="contained" 
                      color="primary"
                      onClick={() => setCurrentTab(1)}
                      endIcon={<EditIcon />}
                    >
                      Proceed to Signing
                    </Button>
                  </Box>
                </Grid>
              </>
            )}
          </Grid>
        )}
        
        {/* Tab 2: Sign Token */}
        {currentTab === 1 && (
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Signing Configuration
                </Typography>
                
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth sx={{ mb: 2 }}>
                      <InputLabel id="algorithm-select-label">Signing Algorithm</InputLabel>
                      <Select
                        labelId="algorithm-select-label"
                        value={algorithm}
                        label="Signing Algorithm"
                        onChange={handleAlgorithmChange}
                      >
                        {algorithms.map((alg) => (
                          <MenuItem key={alg} value={alg}>
                            {alg}
                          </MenuItem>
                        ))}
                      </Select>
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>
                        {getAlgorithmHelp(algorithm)}
                      </Typography>
                    </FormControl>
                  </Grid>
                  
                  <Grid item xs={12} md={6}>
                    <Box sx={{ position: 'relative' }}>
                      <TextField
                        label={algorithm === 'none' ? 'Secret (optional)' : 'Secret'}
                        variant="outlined"
                        fullWidth
                        multiline
                        rows={4}
                        value={secret}
                        onChange={handleSecretChange}
                        placeholder={algorithm.startsWith('RS') || algorithm.startsWith('ES') ? 
                          '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----' : 
                          'your-secret-key'}
                        disabled={algorithm === 'none'}
                        sx={{ mb: 1 }}
                      />
                      <Chip
                        icon={<HelpOutlineIcon />}
                        label={secretHelp()}
                        variant="outlined"
                        size="small"
                        sx={{ mt: 1 }}
                      />
                    </Box>
                  </Grid>
                </Grid>
                
                <Divider sx={{ my: 3 }} />
                
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Button 
                    variant="outlined"
                    onClick={() => setCurrentTab(0)}
                  >
                    Back to Editor
                  </Button>
                  
                  <Button 
                    variant="contained" 
                    color="primary"
                    onClick={generateToken}
                    disabled={loading || (!secret && algorithm !== 'none')}
                    endIcon={loading ? <CircularProgress size={20} /> : <PublishIcon />}
                  >
                    {loading ? 'Generating...' : 'Generate Token'}
                  </Button>
                </Box>
              </Paper>
            </Grid>
          </Grid>
        )}
        
        {/* Tab 3: Result */}
        {currentTab === 2 && (
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Generated Token
                </Typography>
                
                <Alert severity="success" sx={{ mb: 3 }}>
                  Token successfully created with algorithm: <strong>{algorithm}</strong>
                </Alert>
                
                <Box 
                  sx={{ 
                    position: 'relative',
                    mb: 3,
                    p: 3,
                    bgcolor: 'background.default',
                    borderRadius: 2,
                    overflowWrap: 'break-word',
                    fontFamily: 'monospace',
                    fontSize: '14px'
                  }}
                >
                  {modifiedToken}
                  
                  <CopyToClipboard text={modifiedToken} onCopy={handleCopy}>
                    <Button 
                      startIcon={copied ? <CheckCircleIcon /> : <ContentCopyIcon />}
                      variant="contained"
                      size="small"
                      sx={{ 
                        position: 'absolute', 
                        top: 10, 
                        right: 10,
                        bgcolor: copied ? 'success.main' : 'primary.main'  
                      }}
                    >
                      {copied ? 'Copied!' : 'Copy'}
                    </Button>
                  </CopyToClipboard>
                </Box>
                
                <Divider sx={{ my: 3 }} />
                
                <Box className="jwt-token-display">
                  <span className="jwt-token-header">{modifiedToken.split('.')[0]}</span>
                  <span className="jwt-token-dot">.</span>
                  <span className="jwt-token-payload">{modifiedToken.split('.')[1]}</span>
                  <span className="jwt-token-dot">.</span>
                  <span className="jwt-token-signature">{modifiedToken.split('.')[2]}</span>
                </Box>
                
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
                  <Button 
                    variant="outlined"
                    onClick={() => setCurrentTab(1)}
                  >
                    Back to Signing
                  </Button>
                  
                  <Button 
                    variant="contained" 
                    color="primary"
                    onClick={() => {
                      setToken(modifiedToken);
                      decodeToken(modifiedToken);
                      setCurrentTab(0);
                    }}
                  >
                    Edit This Token
                  </Button>
                </Box>
              </Paper>
            </Grid>
          </Grid>
        )}
      </motion.div>
    </Container>
  );
};

export default PayloadEditor; 