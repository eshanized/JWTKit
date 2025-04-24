# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously at JWTKit. If you discover a security vulnerability, please follow these steps:

1. **Do NOT open a public issue**
2. Email us at m.eshanized@gmail.com with:
   - A description of the vulnerability
   - Steps to reproduce (if possible)
   - Potential impact
   - Any suggestions for remediation

We strive to respond to security reports within 48 hours and will keep you updated throughout the process.

### What to expect
1. Acknowledgment of your report within 48 hours
2. Regular updates on our progress
3. Credit for your discovery (unless you prefer to remain anonymous)
4. Notification when the vulnerability is fixed

### Security Best Practices
When using JWTKit:
- Always use strong secrets for HMAC algorithms
- Prefer asymmetric algorithms (RS256, ES256) over symmetric ones
- Keep your private keys secure
- Regularly rotate your keys
- Monitor the audit logs for suspicious activity