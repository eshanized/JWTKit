#!/usr/bin/env python3

"""
JWT Token Generator for JWTKit
"""

import jwt
import json
import uuid
import secrets
from datetime import datetime, timedelta
import argparse

try:
    from jwt_utils import generate_rsa_key_pair
except ImportError:
    print("Warning: jwt_utils not found. RSA key generation disabled.")
    
    def generate_rsa_key_pair():
        return None, None

def generate_secure_secret(length=32):
    """Generate a cryptographically secure random string"""
    return secrets.token_hex(length)

def generate_hs256_token(secret=None, expiration_days=1, claims=None):
    """Generate a secure HS256 token with appropriate claims"""
    if secret is None:
        secret = generate_secure_secret()
        print(f"Generated secure secret: {secret}")
    
    # Default claims
    default_claims = {
        'sub': str(uuid.uuid4()),
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=expiration_days),
        'jti': str(uuid.uuid4()),
    }
    
    # Merge with custom claims if provided
    payload = default_claims.copy()
    if claims:
        payload.update(claims)
    
    token = jwt.encode(payload, secret, algorithm='HS256')
    return token, secret

def generate_rs256_token(claims=None):
    """Generate a secure RS256 token with a new key pair"""
    private_key, public_key = generate_rsa_key_pair()
    if not private_key:
        print("Error: Could not generate RSA keys. Make sure cryptography is installed.")
        return None, None, None
    
    # Default claims
    default_claims = {
        'sub': str(uuid.uuid4()),
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=1),
        'jti': str(uuid.uuid4()),
    }
    
    # Merge with custom claims if provided
    payload = default_claims.copy()
    if claims:
        payload.update(claims)
    
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token, private_key, public_key

def main():
    parser = argparse.ArgumentParser(description='Generate JWT tokens for testing')
    parser.add_argument('--alg', choices=['HS256', 'RS256', 'none'], default='HS256', help='JWT algorithm to use')
    parser.add_argument('--secret', help='Secret key for HMAC algorithms')
    parser.add_argument('--exp', type=int, default=1, help='Expiration time in days')
    parser.add_argument('--claims', help='JSON string with custom claims')
    
    args = parser.parse_args()
    
    # Parse custom claims if provided
    custom_claims = None
    if args.claims:
        try:
            custom_claims = json.loads(args.claims)
        except json.JSONDecodeError:
            print("Error: Invalid JSON in claims")
            return
    
    if args.alg == 'HS256':
        token, secret = generate_hs256_token(args.secret, args.exp, custom_claims)
        print("\n===== HS256 Token =====")
        print(token)
        print("\n===== Secret =====")
        print(secret)
    
    elif args.alg == 'RS256':
        token, private_key, public_key = generate_rs256_token(custom_claims)
        if token:
            print("\n===== RS256 Token =====")
            print(token)
            print("\n===== RSA Private Key =====")
            print(private_key)
            print("\n===== RSA Public Key =====")
            print(public_key)
    
    elif args.alg == 'none':
        print("\nWarning: 'none' algorithm should only be used for testing vulnerabilities")
        # Implementation left for educational purposes
        # Not providing actual implementation to prevent misuse

if __name__ == "__main__":
    main() 