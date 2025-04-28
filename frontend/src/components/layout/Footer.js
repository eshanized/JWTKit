import React from 'react';
import { Box, Typography, Link, Container } from '@mui/material';

const Footer = () => {
  return (
    <Box 
      component="footer" 
      sx={{ 
        py: 2, 
        mt: 'auto',
        borderTop: '1px solid rgba(0, 0, 0, 0.12)',
        backgroundColor: 'background.paper' 
      }}
    >
      <Container maxWidth="lg">
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            &copy; {new Date().getFullYear()} JWTKit - The Ultimate JWT Security Toolkit
          </Typography>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <Link href="https://github.com/eshanized/JWTKit" color="text.secondary" underline="hover" variant="body2">
              GitHub
            </Link>
            <Link href="#" color="text.secondary" underline="hover" variant="body2">
              Documentation
            </Link>
            <Link href="#" color="text.secondary" underline="hover" variant="body2">
              API
            </Link>
          </Box>
        </Box>
      </Container>
    </Box>
  );
};

export default Footer;
