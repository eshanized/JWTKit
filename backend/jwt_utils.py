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

def decode_token_parts(token):
    """
    Decode a JWT without verification and return its parts.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, None, "Invalid JWT format"
        
        # Decode header and payload
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        payload_json = base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8')
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        return header, payload, parts[2], None
    except Exception as e:
        return None, None, None, f"Error decoding token: {str(e)}"

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

def verify_token(token, key, algorithms=None):
    """
    Verify a JWT token signature.
    
    Args:
        token: The JWT token to verify
        key: The key to use for verification (secret for HS*, public key for RS*)
        algorithms: List of allowed algorithms
        
    Returns:
        (is_valid, payload or error message)
    """
    if algorithms is None:
        # Try to extract algorithm from token header
        try:
            header, _, _, error = decode_token_parts(token)
            if error:
                return False, error
            if header is None:
                return False, "Could not decode token header"
            algorithms = [header.get('alg', 'HS256')]
        except Exception as e:
            return False, f"Error determining algorithm: {str(e)}"
    
    try:
        # Verify the token
        payload = jwt.decode(token, key, algorithms=algorithms)
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, "Token has expired"
    except jwt.InvalidTokenError as e:
        return False, f"Invalid token: {str(e)}" 