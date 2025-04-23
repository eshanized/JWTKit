# JWTKit Backend API

This is the backend API for JWTKit, a comprehensive JWT analysis and security testing tool.

## Getting Started

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the server:
   ```
   python main.py
   ```

The API will be available at http://localhost:8000

## API Endpoints

### Health Check
- `GET /`
  - Returns the API status

### JWT Analysis
- `POST /decode`
  - Decodes a JWT without verification
  - Request: `{ "token": "your.jwt.token" }`

- `POST /verify`
  - Verifies a JWT signature
  - Request: `{ "token": "your.jwt.token", "secret": "your-secret", "algorithm": "HS256" }`

- `POST /vulnerabilities`
  - Scans a JWT for common vulnerabilities
  - Request: `{ "token": "your.jwt.token" }`

### JWT Manipulation
- `POST /modify`
  - Modifies a JWT payload and re-signs it
  - Request: `{ "token": "your.jwt.token", "new_payload": {}, "secret": "your-secret", "algorithm": "HS256" }`

### JWT Attack Simulations
- `POST /algorithm-confusion`
  - Attempts algorithm confusion attack (RS256 to HS256)
  - Request: `{ "token": "your.jwt.token", "public_key": "-----BEGIN PUBLIC KEY-----..." }`

- `POST /brute-force`
  - Attempts to brute force a JWT secret
  - Request: `{ "token": "your.jwt.token", "wordlist": ["secret1", "secret2", ...] }`

### Key Generation
- `POST /generate-keys`
  - Generates an RSA key pair for signing JWTs
  - Response: `{ "private_key": "...", "public_key": "..." }`

- `GET /generate-sample-tokens`
  - Generates sample tokens for testing
  - Response: `{ "hs256_token": "...", "rs256_token": "...", "secret": "...", "private_key": "...", "public_key": "..." }`

## Understanding JWT Security

### JWT Structure
A JWT consists of three parts: header, payload, and signature, separated by dots:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Common Vulnerabilities

1. **None Algorithm**
   - JWTs with `"alg": "none"` bypass signature verification
   - Vulnerability: Accepting tokens without verifying signatures

2. **Algorithm Confusion**
   - Switching from RS256 (asymmetric) to HS256 (symmetric)
   - Vulnerability: Using the public key as an HMAC secret

3. **Weak Secrets**
   - Using weak or guessable secrets for HMAC algorithms
   - Vulnerability: Secrets can be brute-forced

4. **Missing Expiration**
   - Tokens without an expiration time (`exp` claim)
   - Vulnerability: Tokens remain valid indefinitely

5. **Insufficient Validation**
   - Not validating issuer, audience, or other claims
   - Vulnerability: Accepting tokens from untrusted sources

### Best Practices
- Use strong algorithm (RS256, ES256)
- Always include expiration time
- Validate issuer and audience claims
- Use strong, unique secrets for HMAC algorithms
- Implement proper key rotation

## Educational Purpose
This tool is meant for educational purposes and security research. Only use against your own systems or with explicit permission. 