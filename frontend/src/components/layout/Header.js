import React from 'react';
import { AppBar, Toolbar, Typography, IconButton, Box, Tooltip, Button } from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import LightModeIcon from '@mui/icons-material/LightMode';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import GitHubIcon from '@mui/icons-material/GitHub';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';

const Header = ({ toggleSidebar, toggleDarkMode, darkMode }) => {
  const navigate = useNavigate();

  return (
    <AppBar position="static" elevation={0} sx={{ borderBottom: '1px solid rgba(0, 0, 0, 0.12)' }}>
      <Toolbar>
        <IconButton
          color="inherit"
          aria-label="open drawer"
          onClick={toggleSidebar}
          edge="start"
          sx={{ mr: 2 }}
        >
          <MenuIcon />
        </IconButton>
        
        <motion.div 
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }} onClick={() => navigate('/')}>
            <img src="/logo.svg" alt="JWTKit Logo" style={{ height: '32px', marginRight: '10px' }} />
            <Typography variant="h6" component="div" sx={{ fontWeight: 'bold' }}>
              JWTKit
            </Typography>
          </Box>
        </motion.div>
        
        <Box sx={{ flexGrow: 1 }} />
        
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Documentation">
            <IconButton color="inherit" aria-label="Documentation">
              <HelpOutlineIcon />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="GitHub Repository">
            <IconButton color="inherit" aria-label="GitHub Repository">
              <GitHubIcon />
            </IconButton>
          </Tooltip>
          
          <Tooltip title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}>
            <IconButton 
              color="inherit" 
              onClick={toggleDarkMode} 
              aria-label={darkMode ? 'Light Mode' : 'Dark Mode'}
            >
              {darkMode ? <LightModeIcon /> : <DarkModeIcon />}
            </IconButton>
          </Tooltip>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Header;