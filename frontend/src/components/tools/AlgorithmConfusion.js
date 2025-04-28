import React, { useState } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { toast } from 'react-toastify';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { 
  Container, Typography, TextField, Button, 
  Box, Paper, Grid, CircularProgress,
  Stepper, Step, StepLabel, StepContent,
  Alert, AlertTitle, Divider, Chip
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import SendIcon from '@mui/icons-material/Send';
import WarningIcon from '@mui/icons-material/Warning';
import SecurityIcon from '@mui/icons-material/Security';
import ReactJson from 'react-json-view';

const AlgorithmConfusion = () => {
  const [token, setToken] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [activeStep, setActiveStep] = useState(0);
  
  const handleTokenChange = (e) => {
    setToken(e.target.value);
  };
  
  const handlePublicKeyChange = (e) => {
    setPublicKey(e.target.value);
  };
  
  const executeAttack = async () => {
    if (!token || !publicKey) {
      toast.error('Please provide both a token and a public key');
      return;
    }
    
    try {
      setLoading(true);
      
      const response = await axios.post('/algorithm-confusion', {
        token,
        public_key: publicKey
      });
      
      setResult(response.data);
      setActiveStep(3);
      toast.success('Algorithm confusion attack executed successfully!');
    } catch (error) {
      console.error('Error executing attack:', error);
      
      if (error.response) {
        toast.error(error.response.data.error || 'Server error');
      } else {
        toast.error('Network error');
      }
    } finally {
      setLoading(false);
    }
  };
  
  const handleStepChange = (step) => {
    setActiveStep(step);
  };
  
  const steps = [
    {
      label: 'Understand the Attack',
      description: (
        <Box>
          <Typography variant="body2" paragraph>
            Algorithm confusion (or algorithm substitution) exploits implementations that don't validate
            the algorithm used for verification matches the one specified in the token's header.
          </Typography>
          <Typography variant="body2" paragraph>
            In this attack, we'll attempt to make a server validate an RS256 (asymmetric) signed token 
            using the HS256 (symmetric) algorithm with the public key as the secret.
          </Typography>
          <Alert severity="warning" sx={{ mt: 2 }}>
            <AlertTitle>IMPORTANT</AlertTitle>
            This is for educational purposes only. Do not use this on systems without permission.
          </Alert>
        </Box>
      )
    },
    {
      label: 'Provide an RS256 Token',
      description: (
        <Box>
          <Typography variant="body2" paragraph>
            Enter a JWT token that was signed with RS256 algorithm.
          </Typography>
          <TextField
            label="JWT Token"
            variant="outlined"
            fullWidth
            multiline
            rows={4}
            value={token}
            onChange={handleTokenChange}
            placeholder="Paste your RS256 JWT token here"
          />
        </Box>
      )
    },
    {
      label: 'Provide the Public Key',
      description: (
        <Box>
          <Typography variant="body2" paragraph>
            Enter the public key that corresponds to the private key used to sign the token.
            The server might be using this public key to verify the token signature.
          </Typography>
          <TextField
            label="Public Key (PEM format)"
            variant="outlined"
            fullWidth
            multiline
            rows={6}
            value={publicKey}
            onChange={handlePublicKeyChange}
            placeholder="Paste the public key in PEM format here"
          />
        </Box>
      )
    },
    {
      label: 'Execute and Analyze',
      description: (
        <Box>
          <Typography variant="body2" paragraph>
            The attack will attempt to trick a server into accepting a token signed with RS256 
            by validating it with HS256 using the public key as the secret.
          </Typography>
          <Button
            variant="contained"
            color="primary"
            endIcon={<SendIcon />}
            onClick={executeAttack}
            disabled={!token || !publicKey || loading}
          >
            {loading ? <CircularProgress size={24} color="inherit" /> : 'Execute Attack'}
          </Button>
        </Box>
      )
    }
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
            Algorithm Confusion Attack
          </Typography>
          <Chip 
            icon={<WarningIcon />} 
            label="OFFENSIVE TECHNIQUE" 
            color="warning" 
            variant="outlined" 
          />
        </Box>
        
        <Grid container spacing={4}>
          <Grid item xs={12} md={4}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Stepper activeStep={activeStep} orientation="vertical">
                {steps.map((step, index) => (
                  <Step key={index}>
                    <StepLabel
                      optional={
                        index === 0 ? (
                          <Typography variant="caption">Background</Typography>
                        ) : null
                      }
                    >
                      {step.label}
                    </StepLabel>
                    <StepContent>
                      {step.description}
                      <Box sx={{ mt: 2 }}>
                        {index < steps.length - 1 && (
                          <Button
                            variant="contained"
                            onClick={() => handleStepChange(index + 1)}
                            sx={{ mt: 1, mr: 1 }}
                          >
                            Continue
                          </Button>
                        )}
                        {index > 0 && (
                          <Button
                            onClick={() => handleStepChange(index - 1)}
                            sx={{ mt: 1, mr: 1 }}
                          >
                            Back
                          </Button>
                        )}
                      </Box>
                    </StepContent>
                  </Step>
                ))}
              </Stepper>
            </Paper>
          </Grid>
          
          <Grid item xs={12} md={8}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Box sx={{ mb: 3 }}>
                <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SecurityIcon color="primary" />
                  How Algorithm Confusion Works
                </Typography>
                <Divider sx={{ my: 2 }} />
                
                <Typography variant="body2" paragraph>
                  The attack exploits systems that don't properly validate the algorithm used for signature verification.
                  When a token is signed with RS256 (RSA + SHA256), it's supposed to be verified using the corresponding
                  public key and the same algorithm.
                </Typography>
                
                <Box sx={{ mb: 2, p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Normal Verification Flow:
                  </Typography>
                  <Typography variant="body2" component="div" sx={{ fontFamily: 'monospace', fontSize: 14 }}>
                    1. Client sends token with header: &#123; "alg": "RS256" &#125;<br />
                    2. Server verifies using RS256 algorithm + public key
                  </Typography>
                </Box>
                
                <Box sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Attack Flow:
                  </Typography>
                  <Typography variant="body2" component="div" sx={{ fontFamily: 'monospace', fontSize: 14 }}>
                    1. Client sends token with header: &#123; "alg": "HS256" &#125;<br />
                    2. Vulnerable server uses HS256 + public key as secret<br />
                    3. Comparison passes because the signature was created with the same method
                  </Typography>
                </Box>
              </Box>
              
              {result && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.2 }}
                >
                  <Typography variant="h6" gutterBottom>
                    Attack Results
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  
                  <Box sx={{ mb: 3 }}>
                    {result.vulnerable ? (
                      <Alert severity="error" sx={{ mb: 2 }}>
                        <AlertTitle>Vulnerable!</AlertTitle>
                        The system is vulnerable to algorithm confusion attacks.
                      </Alert>
                    ) : (
                      <Alert severity="success" sx={{ mb: 2 }}>
                        <AlertTitle>Not Vulnerable</AlertTitle>
                        The system correctly validates algorithm types.
                      </Alert>
                    )}
                    
                    {result.modified_token && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom>
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
                          {result.modified_token}
                          <CopyToClipboard text={result.modified_token} onCopy={() => toast.success('Token copied!')}>
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
                      <Typography variant="subtitle2" gutterBottom>
                        Full Response:
                      </Typography>
                      <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 2 }}>
                        <ReactJson 
                          src={result} 
                          name={false} 
                          displayDataTypes={false}
                          enableClipboard={false}
                          style={{ backgroundColor: 'transparent' }}
                          collapsed={1}
                        />
                      </Box>
                    </Box>
                  </Box>
                  
                  <Alert severity="info" sx={{ mt: 4 }}>
                    <AlertTitle>Mitigation</AlertTitle>
                    <Typography variant="body2">
                      To prevent this attack, always validate that the algorithm in the token header
                      matches the expected algorithm before verification. Additionally, use a strong
                      library that includes algorithm validation by default.
                    </Typography>
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

export default AlgorithmConfusion; 