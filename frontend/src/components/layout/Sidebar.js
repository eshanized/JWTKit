import React from 'react';
import { Drawer, List, ListItem, ListItemIcon, ListItemText, Typography, Box, Divider } from '@mui/material';
import { useNavigate, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';

// Icons
import DashboardIcon from '@mui/icons-material/Dashboard';
import SearchIcon from '@mui/icons-material/Search';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import SecurityIcon from '@mui/icons-material/Security';
import EditIcon from '@mui/icons-material/Edit';
import WarningIcon from '@mui/icons-material/Warning';
import SpeedIcon from '@mui/icons-material/Speed';
import KeyIcon from '@mui/icons-material/Key';
import CloudIcon from '@mui/icons-material/Cloud';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import BugReportIcon from '@mui/icons-material/BugReport';

const Sidebar = ({ isOpen }) => {
  const navigate = useNavigate();
  const location = useLocation();
  
  const items = [
    { name: 'Dashboard', path: '/', icon: <DashboardIcon /> },
    { name: 'JWT Decoder', path: '/decode', icon: <SearchIcon /> },
    { name: 'Signature Verifier', path: '/verify', icon: <VerifiedUserIcon /> },
    { name: 'Vulnerability Scanner', path: '/scan', icon: <SecurityIcon /> },
    { name: 'Payload Editor', path: '/edit', icon: <EditIcon /> },
    { divider: true, title: 'Attack Vectors' },
    { name: 'Algorithm Confusion', path: '/algorithm-confusion', icon: <WarningIcon /> },
    { name: 'Brute Force Attack', path: '/brute-force', icon: <SpeedIcon /> },
    { name: 'Key Injection', path: '/key-injection', icon: <KeyIcon /> },
    { name: 'JWKS Spoofing', path: '/jwks-spoofing', icon: <CloudIcon /> },
    { name: 'Expiration Bypass', path: '/expiration-bypass', icon: <AccessTimeIcon /> },
    { divider: true, title: 'Testing' },
    { name: 'Security Tester', path: '/security-tester', icon: <BugReportIcon /> }
  ];
  
  const listItem = {
    hover: { backgroundColor: 'rgba(74, 144, 226, 0.1)', color: '#4A90E2' },
  };
  
  return (
    <Drawer
      variant="persistent"
      open={isOpen}
      sx={{
        width: 280,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: 280,
          boxSizing: 'border-box',
          border: 'none',
          borderRight: '1px solid rgba(0, 0, 0, 0.12)',
        },
      }}
    >
      <Box sx={{ height: 64 }} /> {/* Spacer for header height */}
      
      <List sx={{ px: 1 }}>
        {items.map((item, index) => (
          item.divider ? (
            <Box key={index} sx={{ mt: 2, mb: 1 }}>
              <Divider />
              <Typography 
                variant="overline" 
                sx={{ 
                  display: 'block', 
                  color: 'text.secondary', 
                  px: 2, 
                  mt: 2, 
                  fontWeight: 'bold' 
                }}
              >
                {item.title}
              </Typography>
            </Box>
          ) : (
            <motion.div key={index} whileHover="hover">
              <ListItem 
                button 
                component={motion.div}
                variants={listItem}
                onClick={() => navigate(item.path)}
                selected={location.pathname === item.path}
                sx={{ 
                  mb: 0.5, 
                  borderRadius: 2, 
                  '&.Mui-selected': { 
                    backgroundColor: 'primary.main',
                    color: 'white',
                    '& .MuiListItemIcon-root': {
                      color: 'white',
                    },
                  } 
                }}
              >
                <ListItemIcon 
                  sx={{ 
                    color: location.pathname === item.path ? 'white' : 'text.secondary',
                    minWidth: '40px'
                  }}
                >
                  {item.icon}
                </ListItemIcon>
                <ListItemText primary={item.name} />
              </ListItem>
            </motion.div>
          )
        ))}
      </List>
    </Drawer>
  );
};

export default Sidebar; 