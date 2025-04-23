from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import base64
import os
from datetime import datetime, timedelta
import jwt
import uuid
import hmac
import hashlib
import random
import string
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import serialization
import logging

# Try to import PyJWT properly
try:
    import jwt
    has_jwt = True
except ImportError:
    # Create a dummy implementation for offline/demo mode
    has_jwt = False
    
    class DummyJWT:
        class ExpiredSignatureError(Exception): pass
        class InvalidTokenError(Exception): pass
        
        @staticmethod
        def decode(*args, **kwargs):
            raise DummyJWT.InvalidTokenError("This is a dummy implementation")
            
        @staticmethod
        def encode(*args, **kwargs):
            # Just return a fake token
            return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    jwt = DummyJWT

# Try to import the JWT utilities
try:
    from jwt_utils import create_sample_token
    has_jwt_utils = True
except ImportError:
    has_jwt_utils = False

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "status": "running",
        "message": "JWT Toolkit API is running"
    })

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    """
    Generate RSA key pair for asymmetric algorithms.
    """
    try:
        key_size = request.json.get('key_size', 2048) if request.json else 2048
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return jsonify({
            "private_key": private_pem,
            "public_key": public_pem,
            "key_size": key_size,
            "type": "RSA"
        })
    except Exception as e:
        return jsonify({"error": f"Error generating RSA key pair: {str(e)}"}), 500

@app.route('/generate-sample-tokens', methods=['GET'])
def generate_sample_tokens():
    """
    Generate sample JWTs using various algorithms
    """
    try:
        # Get sample keys for each algorithm
        sample_keys = {}
        
        # Create HMAC keys
        sample_keys['HS256'] = {
            'type': 'HMAC',
            'algorithm': 'HS256',
            'secret': base64.b64encode(os.urandom(32)).decode('utf-8'),
        }
        
        sample_keys['HS384'] = {
            'type': 'HMAC',
            'algorithm': 'HS384',
            'secret': base64.b64encode(os.urandom(48)).decode('utf-8'),
        }
        
        sample_keys['HS512'] = {
            'type': 'HMAC',
            'algorithm': 'HS512',
            'secret': base64.b64encode(os.urandom(64)).decode('utf-8'),
        }
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Save RSA keys
        sample_keys['RS256'] = {
            'type': 'RSA',
            'algorithm': 'RS256',
            'private_key': private_pem,
            'public_key': public_pem,
        }
        
        # We can reuse RSA keys for PS algorithms
        sample_keys['PS256'] = {
            'type': 'RSA-PSS',
            'algorithm': 'PS256',
            'private_key': private_pem,
            'public_key': public_pem,
        }
        
        # Generate EC key pair
        ec_private_key = ec.generate_private_key(
            curve=ec.SECP256R1()
        )
        
        ec_private_pem = ec_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        ec_public_pem = ec_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Save EC keys
        sample_keys['ES256'] = {
            'type': 'EC',
            'algorithm': 'ES256',
            'private_key': ec_private_pem,
            'public_key': ec_public_pem,
        }
        
        # Generate Ed25519 key pair
        ed_private_key = ed25519.Ed25519PrivateKey.generate()
        
        ed_private_pem = ed_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        ed_public_pem = ed_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Save EdDSA keys
        sample_keys['EdDSA'] = {
            'type': 'EdDSA',
            'algorithm': 'EdDSA',
            'private_key': ed_private_pem,
            'public_key': ed_public_pem,
        }
        
        # Create a standard payload
        payload = {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": True,
            "iat": int(datetime.now().timestamp()),
            "exp": int((datetime.now() + timedelta(days=1)).timestamp())
        }
        
        # Generate tokens with all algorithms
        tokens = {}
        
        # HMAC algorithms
        for alg in ['HS256', 'HS384', 'HS512']:
            tokens[alg] = {
                'token': jwt.encode(payload, sample_keys[alg]['secret'], algorithm=alg),
                'algorithm': alg,
                'secret': sample_keys[alg]['secret'],
                'payload': payload
            }
        
        # RSA algorithms
        for alg in ['RS256', 'PS256']:
            tokens[alg] = {
                'token': jwt.encode(payload, sample_keys[alg]['private_key'], algorithm=alg),
                'algorithm': alg,
                'public_key': sample_keys[alg]['public_key'],
                'payload': payload
            }
        
        # ECDSA algorithms
        tokens['ES256'] = {
            'token': jwt.encode(payload, sample_keys['ES256']['private_key'], algorithm='ES256'),
            'algorithm': 'ES256',
            'public_key': sample_keys['ES256']['public_key'],
            'payload': payload
        }
        
        # EdDSA algorithm
        tokens['EdDSA'] = {
            'token': jwt.encode(payload, sample_keys['EdDSA']['private_key'], algorithm='EdDSA'),
            'algorithm': 'EdDSA',
            'public_key': sample_keys['EdDSA']['public_key'],
            'payload': payload
        }
        
        # None algorithm (unsigned token)
        header = {"alg": "none", "typ": "JWT"}
        header_encoded = base64.b64encode(json.dumps(header).encode()).decode('utf-8').replace('=', '')
        payload_encoded = base64.b64encode(json.dumps(payload).encode()).decode('utf-8').replace('=', '')
        
        tokens['none'] = {
            'token': f"{header_encoded}.{payload_encoded}.",
            'algorithm': 'none',
            'payload': payload,
            'warning': 'This token has no signature and should only be used for testing!'
        }
        
        return jsonify({
            'tokens': tokens,
            'info': 'Sample tokens for testing JWT verification with different algorithms'
        })
        
    except Exception as e:
        return jsonify({"error": f"Error generating sample tokens: {str(e)}"}), 500

@app.route('/decode', methods=['POST'])
def decode_token():
    """
    Decode a JWT and return its components.
    """
    data = request.json or {}
    token = data.get('token', '')
    
    try:
        # Split the token into parts
        parts = token.split('.')
        if len(parts) != 3:
            return jsonify({"error": "Invalid JWT format"}), 400
        
        # Decode header and payload
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        payload_json = base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8')
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        return jsonify({
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "is_valid": None  # Validity is unknown without a secret
        })
    except Exception as e:
        return jsonify({"error": f"Error decoding token: {str(e)}"}), 400

@app.route('/verify', methods=['POST'])
def verify_token():
    """
    Verify a JWT signature using the provided secret.
    """
    data = request.json or {}
    token = data.get('token', '')
    secret = data.get('secret', '')
    algorithm = data.get('algorithm') or "HS256"  # Default to HS256 if not specified
    
    try:
        # Verify the token
        decoded = jwt.decode(
            token, 
            secret, 
            algorithms=[algorithm]
        )
        
        return jsonify({
            "valid": True,
            "payload": decoded
        })
    except jwt.ExpiredSignatureError:
        return jsonify({
            "valid": False,
            "error": "Token has expired"
        })
    except jwt.InvalidTokenError as e:
        return jsonify({
            "valid": False,
            "error": f"Invalid token: {str(e)}"
        })

@app.route('/vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    """
    Scan a JWT for common vulnerabilities and misconfigurations.
    """
    data = request.json or {}
    token = data.get('token', '')
    vulnerabilities = []
    
    try:
        # Split and decode parts
        parts = token.split('.')
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        payload_json = base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8')
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        # Check for algorithm vulnerabilities
        if header.get('alg') == 'none':
            vulnerabilities.append({
                "severity": "high",
                "issue": "None Algorithm",
                "description": "The token uses 'none' algorithm which means signature verification is bypassed."
            })
        
        if header.get('alg', '').startswith('HS'):
            vulnerabilities.append({
                "severity": "info",
                "issue": "HMAC Algorithm",
                "description": "The token uses HMAC which might be vulnerable to brute force if a weak secret is used."
            })
            
        # Check for missing or weak expiration
        if 'exp' not in payload:
            vulnerabilities.append({
                "severity": "medium",
                "issue": "No Expiration",
                "description": "The token does not have an expiration time (exp claim)."
            })
            
        # Check current time against expiration
        if 'exp' in payload:
            exp_time = datetime.fromtimestamp(payload['exp'])
            if exp_time < datetime.now():
                vulnerabilities.append({
                    "severity": "info",
                    "issue": "Expired Token",
                    "description": f"Token expired on {exp_time.isoformat()}"
                })
            elif exp_time > datetime.now() + timedelta(days=30):
                vulnerabilities.append({
                    "severity": "low",
                    "issue": "Long Expiration",
                    "description": "Token has a very long expiration time (>30 days)."
                })
                
        # Check for missing issuer/audience
        if 'iss' not in payload:
            vulnerabilities.append({
                "severity": "low",
                "issue": "No Issuer",
                "description": "Token does not specify an issuer (iss claim)."
            })
            
        if 'aud' not in payload:
            vulnerabilities.append({
                "severity": "low",
                "issue": "No Audience",
                "description": "Token does not specify an audience (aud claim)."
            })
        
        return jsonify({
            "token_info": {
                "header": header,
                "payload": payload
            },
            "vulnerabilities": vulnerabilities,
            "risk_score": len(vulnerabilities),
            "recommendations": [
                "Use RS256 instead of HS256 for better security",
                "Always include expiration time (exp) in tokens",
                "Validate issuer and audience claims"
            ]
        })
    except Exception as e:
        return jsonify({"error": f"Error analyzing token: {str(e)}"}), 400

@app.route('/modify', methods=['POST'])
def modify_token():
    """
    Modify a JWT payload and re-sign it.
    """
    data = request.json or {}
    token = data.get('token', '')
    new_payload = data.get('new_payload', {})
    secret = data.get('secret', '')
    private_key = data.get('private_key', '')
    algorithm = data.get('algorithm') or "HS256"
    
    try:
        # First decode the token to extract the header
        parts = token.split('.')
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        header = json.loads(header_json)
        
        # Use the specified algorithm or the one from the token
        algorithm = algorithm or header.get('alg', 'HS256')
        
        # If the token uses 'none' algorithm, create an unsigned token
        if algorithm.lower() == 'none':
            header['alg'] = 'none'
            
            # Encode header and payload
            header_encoded = base64.b64encode(json.dumps(header).encode()).decode('utf-8').replace('=', '')
            payload_encoded = base64.b64encode(json.dumps(new_payload).encode()).decode('utf-8').replace('=', '')
            
            # Return unsigned token
            return jsonify({
                "modified_token": f"{header_encoded}.{payload_encoded}.",
                "algorithm": "none",
                "warning": "This token has no signature and should only be used for testing."
            })
        
        # Choose the appropriate key based on algorithm
        key = None
        
        if algorithm.startswith('HS'):
            if not secret:
                return jsonify({"error": "Secret is required for HMAC algorithms"}), 400
            key = secret
        elif algorithm.startswith(('RS', 'PS', 'ES')) or algorithm == 'EdDSA':
            if not private_key:
                return jsonify({"error": "Private key is required for asymmetric algorithms"}), 400
            key = private_key
        else:
            return jsonify({"error": f"Unsupported algorithm: {algorithm}"}), 400
        
        # Create a new token with the modified payload
        new_token = jwt.encode(
            new_payload,
            key,
            algorithm=algorithm
        )
        
        # PyJWT >=2.0 returns str, <2.0 returns bytes
        if isinstance(new_token, bytes):
            new_token = new_token.decode('utf-8')
            
        return jsonify({
            "modified_token": new_token,
            "algorithm": algorithm
        })
    except Exception as e:
        return jsonify({"error": f"Error modifying token: {str(e)}"}), 400

@app.route('/algorithm-confusion', methods=['POST'])
def algorithm_confusion():
    """
    Attempt an algorithm confusion attack (RS256 to HS256).
    """
    data = request.json or {}
    token = data.get('token', '')
    public_key = data.get('public_key', '')
    
    try:
        # First decode the token to extract parts
        parts = token.split('.')
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        payload_json = base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8')
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        # Verify that the original token uses RS256
        if header.get('alg') != 'RS256':
            return jsonify({
                "success": False,
                "error": "This attack only works on RS256 tokens",
                "original_algorithm": header.get('alg')
            })
        
        # Change the algorithm to HS256
        header['alg'] = 'HS256'
        
        # Create a new token with HS256 using the public key as the HMAC secret
        modified_token = jwt.encode(
            payload,
            public_key,
            algorithm='HS256',
            headers=header
        )
        
        return jsonify({
            "success": True,
            "modified_token": modified_token,
            "attack_type": "Algorithm Confusion (RS256 to HS256)",
            "description": "This attack exploits implementations that don't validate the algorithm type correctly."
        })
    except Exception as e:
        return jsonify({"error": f"Error in algorithm confusion attack: {str(e)}"}), 400

@app.route('/brute-force', methods=['POST'])
def brute_force():
    """
    Attempt to brute force a JWT secret.
    Note: For educational purposes only.
    """
    data = request.json or {}
    token = data.get('token', '')
    wordlist = data.get('wordlist', [])
    
    # This should be implemented with background tasks in a production app
    results = []
    found_secret = None
    
    try:
        parts = token.split('.')
        
        # Try each word in the wordlist
        for word in wordlist[:100]:  # Limit to first 100 for API response time
            try:
                # Try to verify with this secret
                if jwt.decode(token, word, algorithms=["HS256"]):
                    found_secret = word
                    break
            except:
                continue
        
        if found_secret:
            return jsonify({
                "success": True,
                "secret_found": found_secret,
                "message": "Secret found! Token can be forged."
            })
        else:
            return jsonify({
                "success": False,
                "message": "Secret not found in provided wordlist",
                "words_checked": len(wordlist[:100])
            })
    except Exception as e:
        return jsonify({"error": f"Error in brute force attempt: {str(e)}"}), 400

@app.route('/generate-sample-keys', methods=['GET'])
def generate_sample_keys():
    """
    Generate sample keys for all supported algorithms.
    Note: These keys are for testing only and should not be used in production.
    """
    result = {}
    
    # HMAC keys (HS*)
    result['HS256'] = {
        'type': 'HMAC',
        'algorithm': 'HS256',
        'secret': base64.b64encode(os.urandom(32)).decode('utf-8'),
        'note': 'Secret for HMAC-SHA256 algorithm'
    }
    
    result['HS384'] = {
        'type': 'HMAC',
        'algorithm': 'HS384',
        'secret': base64.b64encode(os.urandom(48)).decode('utf-8'),
        'note': 'Secret for HMAC-SHA384 algorithm'
    }
    
    result['HS512'] = {
        'type': 'HMAC',
        'algorithm': 'HS512',
        'secret': base64.b64encode(os.urandom(64)).decode('utf-8'),
        'note': 'Secret for HMAC-SHA512 algorithm'
    }
    
    # RSA keys (RS*)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    result['RS256'] = {
        'type': 'RSA',
        'algorithm': 'RS256',
        'private_key': private_pem,
        'public_key': public_pem,
        'note': 'RSA key pair for RS256 algorithm'
    }
    
    # RSA-PSS keys (PS*)
    # We can reuse the RSA keys
    result['PS256'] = {
        'type': 'RSA-PSS',
        'algorithm': 'PS256',
        'private_key': private_pem,
        'public_key': public_pem,
        'note': 'RSA key pair for PS256 algorithm (same key as RS256, different padding)'
    }
    
    # ECDSA keys (ES*)
    ec_private_key = ec.generate_private_key(
        curve=ec.SECP256R1()
    )
    
    ec_private_pem = ec_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    ec_public_pem = ec_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    result['ES256'] = {
        'type': 'EC',
        'algorithm': 'ES256',
        'private_key': ec_private_pem,
        'public_key': ec_public_pem,
        'note': 'Elliptic Curve key pair for ES256 algorithm'
    }
    
    # EdDSA keys (Ed25519)
    ed_private_key = ed25519.Ed25519PrivateKey.generate()
    
    ed_private_pem = ed_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    ed_public_pem = ed_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    result['EdDSA'] = {
        'type': 'EdDSA',
        'algorithm': 'EdDSA',
        'private_key': ed_private_pem,
        'public_key': ed_public_pem,
        'note': 'Ed25519 key pair for EdDSA algorithm'
    }
    
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True) 