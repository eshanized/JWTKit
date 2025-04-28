import React, { useState } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { toast } from 'react-toastify';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { 
  Container, Typography, TextField, Button, 
  Box, Paper, Grid, CircularProgress,
  Alert, AlertTitle, Divider, Chip, Tab, Tabs,
  List, ListItem, ListItemIcon, ListItemText
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import SendIcon from '@mui/icons-material/Send';
import WarningIcon from '@mui/icons-material/Warning';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import ReactJson from 'react-json-view';

const ExpirationBypass = () => {
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [currentTab, setCurrentTab] = useState(0);
  
  const handleTokenChange = (e) => {
    setToken(e.target.value);
  };
  
  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
  };
  
  const executeAttack = async () => {
    if (!token) {
      toast.error('Please provide a JWT token');
      return;
    }
    
    try {
      setLoading(true);
      
      const attackTypes = [
        'exp_removal',
        'exp_extension',
        'nbf_manipulation',
        'time_confusion'
      ];
      
      const response = await axios.post('/expiration-bypass', {
        token,
        attack_type: attackTypes[currentTab]
      });
      
      setResults(response.data);
      toast.success('Expiration bypass attack executed successfully!');
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
  
  const renderAttackDescription = () => {
    switch (currentTab) {
      case 0: // exp_removal
        return (
          <>
            <Typography variant="body2" paragraph>
              This attack attempts to remove the expiration ('exp') claim from the token's payload.
              If a system doesn't properly validate the presence of required claims, this can allow
              expired tokens to remain valid indefinitely.
            </Typography>
            <Typography variant="body2">
              The modified token will look identical except the 'exp' claim will be removed from the payload.
            </Typography>
          </>
        );
      case 1: // exp_extension
        return (
          <>
            <Typography variant="body2" paragraph>
              This attack extends the expiration time of the token by modifying the 'exp' claim to a
              future date. If the system doesn't verify token integrity properly, this can allow
              expired tokens to be "renewed" by attackers.
            </Typography>
            <Typography variant="body2">
              The modified token will have an extended 'exp' claim, typically set to a far future date.
            </Typography>
          </>
        );
      case 2: // nbf_manipulation
        return (
          <>
            <Typography variant="body2" paragraph>
              This attack manipulates the 'nbf' (Not Before) claim, which specifies when the token starts
              being valid. By setting this to a future date, some systems might have unexpected behavior
              with time validation.
            </Typography>
            <Typography variant="body2">
              The attack works when systems check 'exp' but mishandle or ignore the 'nbf' validation.
            </Typography>
          </>
        );
      case 3: // time_confusion
        return (
          <>
            <Typography variant="body2" paragraph>
              This attack exploits confusion in time format interpretation. Some JWT libraries may interpret
              timestamps in different formats (seconds vs milliseconds). This attack modifies the time claims
              to use a different format than expected.
            </Typography>
            <Typography variant="body2">
              For example, if a system expects seconds but receives milliseconds, an expired token might
              be interpreted as valid for many years into the future.
            </Typography>
          </>
        );
      default:
        return null;
    }
  };
  
  const getTabLabel = (index) => {
    switch(index) {
      case 0: return 'EXP Removal';
      case 1: return 'EXP Extension';
      case 2: return 'NBF Manipulation';
      case 3: return 'Time Confusion';
      default: return 'Unknown';
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
            JWT Expiration Bypass
          </Typography>
          <Chip 
            icon={<WarningIcon />} 
            label="OFFENSIVE TECHNIQUE" 
            color="error" 
            variant="outlined" 
          />
        </Box>
        
        <Alert severity="warning" sx={{ mb: 4 }}>
          <AlertTitle>Educational Purpose Only</AlertTitle>
          <Typography variant="body2">
            This tool is designed to test JWT implementations against expiration bypass techniques.
            Use only for educational purposes and on systems you have permission to test.
          </Typography>
        </Alert>
        
        <Grid container spacing={4}>
          <Grid item xs={12} md={6}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <AccessTimeIcon color="primary" />
                Attack Configuration
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              <Box sx={{ mb: 3 }}>
                <Tabs 
                  value={currentTab} 
                  onChange={handleTabChange}
                  variant="scrollable"
                  scrollButtons="auto"
                  sx={{ mb: 3 }}
                >
                  {[0, 1, 2, 3].map(index => (
                    <Tab key={index} label={getTabLabel(index)} />
                  ))}
                </Tabs>
                
                <Box sx={{ p: 2, bgcolor: 'background.default', borderRadius: 2, mb: 3 }}>
                  {renderAttackDescription()}
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
                
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <SendIcon />}
                  onClick={executeAttack}
                  disabled={loading || !token}
                  fullWidth
                >
                  {loading ? 'Executing...' : 'Execute Attack'}
                </Button>
              </Box>
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
                          The system is vulnerable to {getTabLabel(currentTab)} attack.
                          The modified token was accepted despite expiration manipulation.
                        </Typography>
                      </Alert>
                    ) : (
                      <Alert severity="success" sx={{ mb: 3 }}>
                        <AlertTitle>Not Vulnerable</AlertTitle>
                        <Typography variant="body2">
                          The system correctly validates token expiration claims.
                        </Typography>
                      </Alert>
                    )}
                    
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="subtitle1" gutterBottom>
                        Findings:
                      </Typography>
                      <List>
                        {results.checks && results.checks.map((check, index) => (
                          <ListItem key={index}>
                            <ListItemIcon>
                              {check.passed ? 
                                <CheckCircleOutlineIcon color="success" /> : 
                                <ErrorOutlineIcon color="error" />
                              }
                            </ListItemIcon>
                            <ListItemText 
                              primary={check.name} 
                              secondary={check.description} 
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                    
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
                        Original vs Modified Claims:
                      </Typography>
                      <Grid container spacing={2}>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" gutterBottom>
                            Original Claims:
                          </Typography>
                          <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 2 }}>
                            {results.original_payload && (
                              <ReactJson 
                                src={results.original_payload} 
                                name={false} 
                                displayDataTypes={false}
                                enableClipboard={false}
                                style={{ backgroundColor: 'transparent' }}
                              />
                            )}
                          </Box>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" gutterBottom>
                            Modified Claims:
                          </Typography>
                          <Box sx={{ bgcolor: 'background.default', p: 2, borderRadius: 2 }}>
                            {results.modified_payload && (
                              <ReactJson 
                                src={results.modified_payload} 
                                name={false} 
                                displayDataTypes={false}
                                enableClipboard={false}
                                style={{ backgroundColor: 'transparent' }}
                              />
                            )}
                          </Box>
                        </Grid>
                      </Grid>
                    </Box>
                  </Box>
                  
                  <Divider sx={{ my: 3 }} />
                  
                  <Typography variant="h6" gutterBottom>
                    Security Recommendations
                  </Typography>
                  
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <AlertTitle>Proper JWT Validation</AlertTitle>
                    <ul>
                      <li>Always validate both the token signature and all required claims</li>
                      <li>Ensure all time-related claims (exp, nbf, iat) are properly validated</li>
                      <li>Use a robust JWT library that handles time checks correctly</li>
                      <li>Implement server-side validation of token revocation and expiration</li>
                      <li>Consider additional security measures like short-lived tokens with refresh tokens</li>
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

export default ExpirationBypass; 