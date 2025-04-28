import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { toast } from 'react-toastify';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { 
  Container, Typography, TextField, Button, 
  Box, Paper, Grid, CircularProgress,
  Alert, AlertTitle, Divider, Chip, Accordion,
  AccordionSummary, AccordionDetails, Stack,
  LinearProgress, FormControl, InputLabel,
  Select, MenuItem
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import SecurityIcon from '@mui/icons-material/Security';
import WarningIcon from '@mui/icons-material/Warning';
import LockIcon from '@mui/icons-material/Lock';
import ScheduleIcon from '@mui/icons-material/Schedule';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';

const BruteForceAttack = () => {
  const [token, setToken] = useState('');
  const [wordlist, setWordlist] = useState('common');
  const [maxAttempts, setMaxAttempts] = useState(100);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [progress, setProgress] = useState(0);
  const [attackStatus, setAttackStatus] = useState('idle'); // idle, running, completed, stopped
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [startTime, setStartTime] = useState(null);
  const [timerInterval, setTimerInterval] = useState(null);
  
  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (timerInterval) {
        clearInterval(timerInterval);
      }
    };
  }, [timerInterval]);
  
  const handleTokenChange = (e) => {
    setToken(e.target.value);
  };
  
  const startTimer = () => {
    const now = Date.now();
    setStartTime(now);
    
    const interval = setInterval(() => {
      setTimeElapsed(Math.floor((Date.now() - now) / 1000));
    }, 1000);
    
    setTimerInterval(interval);
  };
  
  const stopTimer = () => {
    if (timerInterval) {
      clearInterval(timerInterval);
      setTimerInterval(null);
    }
  };
  
  const executeAttack = async () => {
    if (!token) {
      toast.error('Please provide a JWT token');
      return;
    }
    
    try {
      setLoading(true);
      setAttackStatus('running');
      setProgress(0);
      startTimer();
      
      // Get the algorithm from the token
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }
      
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const algorithm = header.alg || 'HS256';
      
      const response = await axios.post('/brute-force', {
        token,
        wordlist,
        max_attempts: maxAttempts
      });
      
      setResults(response.data);
      setAttackStatus('completed');
      stopTimer();
      
      if (response.data.success) {
        toast.success('Secret found!');
      } else {
        toast.info('Attack completed without finding the secret');
      }
    } catch (error) {
      console.error('Error executing attack:', error);
      setAttackStatus('idle');
      stopTimer();
      
      if (error.response) {
        toast.error(error.response.data.error || 'Server error');
      } else {
        toast.error('Network error');
      }
    } finally {
      setLoading(false);
    }
  };
  
  const stopAttack = async () => {
    try {
      // This would require a backend endpoint to stop the attack
      await axios.post('/brute-force/stop');
      setAttackStatus('stopped');
      stopTimer();
      toast.info('Attack stopped');
    } catch (error) {
      console.error('Error stopping attack:', error);
      toast.error('Could not stop the attack');
    }
  };
  
  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };
  
  const wordlistOptions = [
    { value: 'common', label: 'Common Passwords (Fast)' },
    { value: 'medium', label: 'Medium Dictionary (Moderate)' },
    { value: 'large', label: 'Large Dictionary (Slow)' },
    { value: 'custom', label: 'Custom Wordlist' }
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
            JWT Brute Force Attack
          </Typography>
          <Chip 
            icon={<WarningIcon />} 
            label="OFFENSIVE TECHNIQUE" 
            color="error" 
            variant="outlined" 
          />
        </Box>
        
        <Alert severity="warning" sx={{ mb: 4 }}>
          <AlertTitle>This tool is for educational purposes only</AlertTitle>
          <Typography variant="body2">
            Testing JWT brute force attacks helps understand the importance of using strong, 
            unique secrets for signing tokens. Never use this tool against systems without explicit permission.
          </Typography>
        </Alert>
        
        <Grid container spacing={4}>
          <Grid item xs={12} md={6}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <LockIcon color="primary" />
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
                
                <FormControl fullWidth sx={{ mb: 3 }}>
                  <InputLabel id="wordlist-select-label">Wordlist</InputLabel>
                  <Select
                    labelId="wordlist-select-label"
                    value={wordlist}
                    label="Wordlist"
                    onChange={(e) => setWordlist(e.target.value)}
                  >
                    {wordlistOptions.map((option) => (
                      <MenuItem key={option.value} value={option.value}>
                        {option.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                
                <TextField
                  label="Maximum Attempts"
                  variant="outlined"
                  fullWidth
                  type="number"
                  value={maxAttempts}
                  onChange={(e) => setMaxAttempts(Math.max(1, parseInt(e.target.value) || 1))}
                  sx={{ mb: 3 }}
                  InputProps={{ inputProps: { min: 1, max: 10000 } }}
                />
                
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <Button
                    variant="contained"
                    color="primary"
                    startIcon={<PlayArrowIcon />}
                    onClick={executeAttack}
                    disabled={!token || loading || attackStatus === 'running'}
                    fullWidth
                  >
                    {loading ? <CircularProgress size={24} color="inherit" /> : 'Start Attack'}
                  </Button>
                  
                  <Button
                    variant="outlined"
                    color="error"
                    startIcon={<StopIcon />}
                    onClick={stopAttack}
                    disabled={attackStatus !== 'running'}
                    fullWidth
                  >
                    Stop
                  </Button>
                </Box>
              </Box>
              
              {attackStatus === 'running' && (
                <Box sx={{ mt: 4 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                    <Typography variant="body2" color="text.secondary">
                      Progress
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {progress}%
                    </Typography>
                  </Box>
                  <LinearProgress 
                    variant="determinate" 
                    value={progress} 
                    sx={{ mb: 2, height: 10, borderRadius: 2 }} 
                  />
                  
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <ScheduleIcon fontSize="small" color="action" />
                    <Typography variant="body2" color="text.secondary">
                      Time Elapsed: {formatTime(timeElapsed)}
                    </Typography>
                  </Box>
                </Box>
              )}
              
              <Accordion 
                elevation={0}
                sx={{ 
                  mt: 3, 
                  bgcolor: 'background.default',
                  '&:before': {
                    display: 'none',
                  },
                }}
              >
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle2">How it works</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" paragraph>
                    This tool attempts to crack a JWT token's secret by trying common passwords 
                    and phrases. The attack works only for tokens signed with symmetric algorithms (HS256, HS384, HS512).
                  </Typography>
                  <Typography variant="body2" paragraph>
                    For each candidate secret, the tool:
                  </Typography>
                  <ol>
                    <li>Takes the header and payload from the token</li>
                    <li>Recalculates the signature using the candidate secret</li>
                    <li>Compares the calculated signature with the original</li>
                    <li>If they match, the secret has been found</li>
                  </ol>
                </AccordionDetails>
              </Accordion>
            </Paper>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Paper elevation={0} sx={{ p: 3, borderRadius: 2 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <SecurityIcon color="primary" />
                Results
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              {attackStatus === 'idle' && !results && (
                <Box sx={{ py: 8, textAlign: 'center' }}>
                  <Typography variant="body1" color="text.secondary">
                    Configure and run the attack to see results here
                  </Typography>
                </Box>
              )}
              
              {results && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.2 }}
                >
                  <Box sx={{ mb: 4 }}>
                    <Stack spacing={2}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="subtitle1">Status:</Typography>
                        {results.success ? (
                          <Chip 
                            icon={<CheckCircleIcon />} 
                            label="SECRET FOUND" 
                            color="success"
                            sx={{ fontWeight: 'bold' }}
                          />
                        ) : (
                          <Chip 
                            label="NOT FOUND" 
                            color="error"
                          />
                        )}
                      </Box>
                      
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="subtitle1">Attempts:</Typography>
                        <Typography variant="body1">{results.attempts}</Typography>
                      </Box>
                      
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="subtitle1">Time Taken:</Typography>
                        <Typography variant="body1">{results.time_taken ? `${results.time_taken.toFixed(2)}s` : formatTime(timeElapsed)}</Typography>
                      </Box>
                      
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="subtitle1">Rate:</Typography>
                        <Typography variant="body1">
                          {results.attempts_per_second ? `${Math.round(results.attempts_per_second)} attempts/sec` : 'N/A'}
                        </Typography>
                      </Box>
                    </Stack>
                    
                    {results.success && (
                      <Box sx={{ mt: 4, p: 2, bgcolor: 'success.light', borderRadius: 2, position: 'relative' }}>
                        <Typography variant="subtitle1" sx={{ color: 'white', mb: 1 }}>
                          Found Secret:
                        </Typography>
                        <Typography 
                          variant="body1" 
                          sx={{ 
                            fontFamily: 'monospace', 
                            color: 'white',
                            wordBreak: 'break-all' 
                          }}
                        >
                          {results.secret}
                        </Typography>
                        <CopyToClipboard text={results.secret} onCopy={() => toast.success('Secret copied!')}>
                          <Button 
                            size="small" 
                            variant="contained"
                            color="success"
                            startIcon={<ContentCopyIcon />}
                            sx={{ position: 'absolute', top: 8, right: 8 }}
                          >
                            Copy
                          </Button>
                        </CopyToClipboard>
                      </Box>
                    )}
                  </Box>
                  
                  <Divider sx={{ my: 3 }} />
                  
                  <Typography variant="h6" gutterBottom>
                    Security Recommendations
                  </Typography>
                  
                  <Stack spacing={2} sx={{ mt: 2 }}>
                    <Alert severity="info">
                      <AlertTitle>Use Strong Secrets</AlertTitle>
                      JWT secrets should be at least 32 characters long with high entropy.
                    </Alert>
                    
                    <Alert severity="info">
                      <AlertTitle>Consider Asymmetric Algorithms</AlertTitle>
                      RS256, ES256 and other asymmetric algorithms are not vulnerable to brute force attacks.
                    </Alert>
                    
                    <Alert severity="info">
                      <AlertTitle>Rotate Keys Regularly</AlertTitle>
                      Even with strong secrets, it's good practice to rotate keys periodically.
                    </Alert>
                  </Stack>
                </motion.div>
              )}
            </Paper>
          </Grid>
        </Grid>
      </motion.div>
    </Container>
  );
};

export default BruteForceAttack; 