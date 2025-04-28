import React from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Box, Typography, Grid, Card, CardContent, 
  CardActions, Button, Container, Paper,
  Chip, Divider
} from '@mui/material';
import { motion } from 'framer-motion';

// Icons
import SearchIcon from '@mui/icons-material/Search';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import SecurityIcon from '@mui/icons-material/Security';
import EditIcon from '@mui/icons-material/Edit';
import WarningIcon from '@mui/icons-material/Warning';
import SpeedIcon from '@mui/icons-material/Speed';
import KeyIcon from '@mui/icons-material/Key';

const Dashboard = () => {
  const navigate = useNavigate();
  
  const mainTools = [
    {
      title: 'Decode JWT',
      description: 'Decode and inspect JWT tokens without sending sensitive data to the server.',
      icon: <SearchIcon fontSize="large" />,
      path: '/decode',
      color: '#4ecdc4'
    },
    {
      title: 'Verify Signature',
      description: 'Verify JWT signatures using various algorithms and keys.',
      icon: <VerifiedUserIcon fontSize="large" />,
      path: '/verify',
      color: '#4A90E2'
    },
    {
      title: 'Scan Vulnerabilities',
      description: 'Analyze tokens for common security issues and vulnerabilities.',
      icon: <SecurityIcon fontSize="large" />,
      path: '/scan',
      color: '#ff6b6b'
    },
    {
      title: 'Edit Payload',
      description: 'Modify JWT payload and create new tokens.',
      icon: <EditIcon fontSize="large" />,
      path: '/edit',
      color: '#ffd166'
    }
  ];
  
  const attackVectors = [
    {
      title: 'Algorithm Confusion',
      description: 'Test for vulnerabilities in signature verification algorithms.',
      icon: <WarningIcon />,
      path: '/algorithm-confusion'
    },
    {
      title: 'Brute Force Attack',
      description: 'Test token resistance against brute force attacks.',
      icon: <SpeedIcon />,
      path: '/brute-force'
    },
    {
      title: 'Key Injection',
      description: 'Attempt to bypass signature verification with key manipulation.',
      icon: <KeyIcon />,
      path: '/key-injection'
    }
  ];
  
  const container = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };
  
  const item = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0 }
  };
  
  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Paper 
          elevation={0} 
          sx={{ 
            p: 4, 
            mb: 4, 
            borderRadius: 3,
            background: 'linear-gradient(45deg, #4A90E2 30%, #6AB8F7 90%)',
            color: 'white'
          }}
        >
          <Typography variant="h4" component="h1" gutterBottom fontWeight="bold">
            Welcome to JWTKit
          </Typography>
          <Typography variant="h6">
            A comprehensive toolkit for JWT analysis, testing, and debugging
          </Typography>
          <Chip 
            label="Open Source" 
            sx={{ 
              mt: 2, 
              color: 'white', 
              bgcolor: 'rgba(255,255,255,0.2)',
              '&:hover': { bgcolor: 'rgba(255,255,255,0.3)' }
            }} 
          />
        </Paper>
      </motion.div>
      
      <Typography variant="h5" component="h2" gutterBottom sx={{ mb: 3, fontWeight: 'bold' }}>
        Core Tools
      </Typography>
      
      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
      >
        <Grid container spacing={3}>
          {mainTools.map((tool, index) => (
            <Grid item xs={12} sm={6} md={3} key={index}>
              <motion.div variants={item}>
                <Card className="tool-card" sx={{ height: '100%' }}>
                  <CardContent>
                    <Box 
                      sx={{ 
                        display: 'flex', 
                        alignItems: 'center',
                        justifyContent: 'center',
                        mb: 2,
                        p: 1.5,
                        borderRadius: '50%',
                        width: 60,
                        height: 60,
                        bgcolor: `${tool.color}20`,
                        color: tool.color
                      }}
                    >
                      {tool.icon}
                    </Box>
                    <Typography variant="h6" component="h3" gutterBottom>
                      {tool.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {tool.description}
                    </Typography>
                  </CardContent>
                  <CardActions>
                    <Button 
                      size="small" 
                      onClick={() => navigate(tool.path)}
                      sx={{ color: tool.color }}
                    >
                      Launch Tool
                    </Button>
                  </CardActions>
                </Card>
              </motion.div>
            </Grid>
          ))}
        </Grid>
      </motion.div>
      
      <Divider sx={{ my: 4 }} />
      
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" component="h2" gutterBottom sx={{ mb: 0, fontWeight: 'bold' }}>
          Attack Vectors
        </Typography>
        <Button 
          variant="outlined" 
          color="primary" 
          size="small"
          onClick={() => navigate('/security-tester')}
        >
          See All Tests
        </Button>
      </Box>
      
      <motion.div variants={container} initial="hidden" animate="show">
        <Grid container spacing={3}>
          {attackVectors.map((tool, index) => (
            <Grid item xs={12} sm={6} md={4} key={index}>
              <motion.div variants={item}>
                <Card className="tool-card" sx={{ height: '100%' }}>
                  <CardContent>
                    <Box 
                      sx={{ 
                        display: 'flex', 
                        alignItems: 'center',
                        mb: 2,
                        gap: 1,
                      }}
                    >
                      <Box 
                        sx={{ 
                          borderRadius: '50%',
                          p: 1,
                          bgcolor: 'rgba(244, 67, 54, 0.1)',
                          color: '#f44336',
                          display: 'flex',
                        }}
                      >
                        {tool.icon}
                      </Box>
                      <Typography variant="h6" component="h3">
                        {tool.title}
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      {tool.description}
                    </Typography>
                  </CardContent>
                  <CardActions>
                    <Button 
                      size="small" 
                      onClick={() => navigate(tool.path)}
                    >
                      Try Attack
                    </Button>
                  </CardActions>
                </Card>
              </motion.div>
            </Grid>
          ))}
        </Grid>
      </motion.div>
      
      <Paper 
        elevation={0} 
        sx={{ 
          p: 3, 
          mt: 4, 
          borderRadius: 3,
          bgcolor: 'background.paper',
          borderLeft: '4px solid #4A90E2'
        }}
      >
        <Typography variant="h6" component="h3" gutterBottom>
          About JWTKit
        </Typography>
        <Typography variant="body2" color="text.secondary">
          JWTKit is an open-source tool for developers and security professionals
          to analyze, test, and debug JSON Web Tokens (JWTs). All JWT operations
          are performed locally in your browser for maximum security.
        </Typography>
      </Paper>
    </Container>
  );
};

export default Dashboard; 