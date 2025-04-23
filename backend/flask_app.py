"""
Main Flask application for JWTKit

This module initializes the Flask application and registers all the API endpoints
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import jwt
import json
import base64
import hashlib
import uuid
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('jwtkit')

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Import our advanced API
try:
    from backend.advanced_api import register_advanced_api
    has_advanced_api = True
    register_advanced_api_fn = register_advanced_api
except ImportError:
    try:
        # Try relative import if the first one fails
        from advanced_api import register_advanced_api
        has_advanced_api = True
        register_advanced_api_fn = register_advanced_api
    except ImportError:
        logger.warning("Advanced API module not found. Advanced features will be disabled.")
        has_advanced_api = False
        register_advanced_api_fn = None

# Setup config
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex()),
    JWT_EXPIRATION=3600,  # 1 hour
    DEBUG=os.environ.get('DEBUG', 'False').lower() == 'true'
)

@app.route('/')
def index():
    """Root endpoint that returns API info"""
    return jsonify({
        "name": "JWTKit API",
        "version": "1.0.0",
        "description": "Advanced JWT analysis, testing, and key management API",
        "documentation": "/docs",
        "advanced_features": has_advanced_api
    })

@app.route('/docs')
def docs():
    """Return API documentation"""
    try:
        # Try to serve static documentation if available
        return send_from_directory('static', 'docs.html')
    except:
        # Otherwise return JSON endpoints documentation
        endpoints = [
            {
                "path": "/",
                "method": "GET",
                "description": "API information"
            },
            {
                "path": "/docs",
                "method": "GET",
                "description": "API documentation"
            },
            {
                "path": "/decode",
                "method": "POST",
                "description": "Decode a JWT token without verification",
                "body": {
                    "token": "JWT token string"
                }
            },
            {
                "path": "/verify",
                "method": "POST",
                "description": "Verify a JWT token",
                "body": {
                    "token": "JWT token string",
                    "secret": "Secret for HS algorithms",
                    "public_key": "Public key for RS/ES algorithms (optional)"
                }
            },
            {
                "path": "/generate",
                "method": "POST",
                "description": "Generate a new JWT token",
                "body": {
                    "payload": "JSON payload object",
                    "secret": "Secret for HS algorithms",
                    "private_key": "Private key for RS/ES algorithms (optional)",
                    "algorithm": "JWT algorithm (default: HS256)"
                }
            }
        ]
        
        # Add advanced endpoints if available
        if has_advanced_api:
            advanced_endpoints = [
                {
                    "path": "/api/v1/health",
                    "method": "GET",
                    "description": "Health check for advanced API"
                },
                {
                    "path": "/api/v1/jwks.json",
                    "method": "GET",
                    "description": "JWKS endpoint serving public keys"
                },
                {
                    "path": "/api/v1/keys",
                    "method": "GET",
                    "description": "List all managed keys",
                    "query": {
                        "include_inactive": "Include inactive keys (true/false)"
                    }
                },
                {
                    "path": "/api/v1/keys",
                    "method": "POST",
                    "description": "Generate a new key",
                    "body": {
                        "type": "Key type (hmac, rsa, ec, ed25519)",
                        "algorithm": "JWT algorithm",
                        "bits/key_size/curve": "Key parameters based on type"
                    }
                },
                {
                    "path": "/api/v1/keys/rotate",
                    "method": "POST",
                    "description": "Rotate keys for an algorithm",
                    "body": {
                        "algorithm": "Algorithm to rotate keys for"
                    }
                },
                {
                    "path": "/api/v1/sign",
                    "method": "POST",
                    "description": "Sign payload with managed keys",
                    "body": {
                        "payload": "JSON payload object",
                        "algorithm": "JWT algorithm",
                        "expiration_seconds": "Token expiration time in seconds",
                        "kid": "Specific key ID to use (optional)"
                    }
                },
                {
                    "path": "/api/v1/verify-managed",
                    "method": "POST",
                    "description": "Verify token with managed keys",
                    "body": {
                        "token": "JWT token string"
                    }
                },
                {
                    "path": "/api/v1/attack-simulation",
                    "method": "POST",
                    "description": "Simulate JWT attacks",
                    "body": {
                        "token": "JWT token string",
                        "public_key": "Public key for certain attacks (optional)",
                        "attack_type": "Specific attack to run (optional)",
                        "wordlist": "Array of secrets for brute force (optional)"
                    }
                },
                {
                    "path": "/api/v1/audit",
                    "method": "POST",
                    "description": "Comprehensive JWT token audit",
                    "body": {
                        "token": "JWT token string"
                    }
                }
            ]
            endpoints.extend(advanced_endpoints)
        
        return jsonify({
            "api": "JWTKit",
            "version": "1.0.0",
            "endpoints": endpoints
        })

@app.route('/decode', methods=['POST'])
def decode_token():
    """Decode a JWT token without verification"""
    data = request.json or {}
    token = data.get('token')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        # Split the token
        parts = token.split('.')
        if len(parts) != 3:
            return jsonify({"error": "Invalid token format"}), 400
            
        # Decode header and payload
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        payload_json = base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8')
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        # Calculate signature size
        signature_bytes = base64.urlsafe_b64decode(parts[2] + '=' * (-len(parts[2]) % 4))
        
        return jsonify({
            "header": header,
            "payload": payload,
            "signature": {
                "raw": parts[2],
                "size_bytes": len(signature_bytes)
            }
        })
    except Exception as e:
        logger.error(f"Error decoding token: {str(e)}")
        return jsonify({"error": f"Failed to decode token: {str(e)}"}), 500

@app.route('/verify', methods=['POST'])
def verify_token():
    """Verify a JWT token"""
    data = request.json or {}
    token = data.get('token')
    secret = data.get('secret')
    public_key = data.get('public_key')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        # Parse the header to get the algorithm
        parts = token.split('.')
        if len(parts) != 3:
            return jsonify({"error": "Invalid token format"}), 400
            
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        header = json.loads(header_json)
        
        algorithm = header.get('alg')
        
        # Choose the appropriate key based on algorithm
        key = None
        if algorithm.startswith('HS'):
            if not secret:
                return jsonify({"error": "Secret is required for HMAC algorithms"}), 400
            key = secret
        elif algorithm.startswith(('RS', 'PS', 'ES')):
            if not public_key:
                return jsonify({"error": "Public key is required for asymmetric algorithms"}), 400
            key = public_key
        elif algorithm == 'none':
            return jsonify({
                "valid": False,
                "error": "'none' algorithm is not secure and is not supported"
            })
        else:
            return jsonify({"error": f"Unsupported algorithm: {algorithm}"}), 400
        
        # Verify the token
        decoded = jwt.decode(token, key, algorithms=[algorithm])
        
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
    except Exception as e:
        logger.error(f"Error verifying token: {str(e)}")
        return jsonify({"error": f"Failed to verify token: {str(e)}"}), 500

@app.route('/generate', methods=['POST'])
def generate_token():
    """Generate a new JWT token"""
    data = request.json or {}
    payload = data.get('payload', {})
    secret = data.get('secret')
    private_key = data.get('private_key')
    algorithm = data.get('algorithm', 'HS256')
    expiration = data.get('expiration_seconds', app.config['JWT_EXPIRATION'])
    
    # Validate inputs
    if algorithm.startswith('HS'):
        if not secret:
            return jsonify({"error": "Secret is required for HMAC algorithms"}), 400
        key = secret
    elif algorithm.startswith(('RS', 'PS', 'ES')):
        if not private_key:
            return jsonify({"error": "Private key is required for asymmetric algorithms"}), 400
        key = private_key
    elif algorithm == 'none':
        return jsonify({"error": "'none' algorithm is not secure and is not supported"}), 400
    else:
        return jsonify({"error": f"Unsupported algorithm: {algorithm}"}), 400
    
    try:
        # Add standard claims if not present
        if 'iat' not in payload:
            payload['iat'] = datetime.utcnow()
            
        if expiration and 'exp' not in payload:
            payload['exp'] = datetime.utcnow() + timedelta(seconds=expiration)
            
        if 'jti' not in payload:
            payload['jti'] = str(uuid.uuid4())
            
        # Generate the token
        token = jwt.encode(payload, key, algorithm=algorithm)
        
        # If token is bytes, convert to string (for PyJWT compatibility)
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        
        return jsonify({
            "token": token,
            "algorithm": algorithm
        })
    except Exception as e:
        logger.error(f"Error generating token: {str(e)}")
        return jsonify({"error": f"Failed to generate token: {str(e)}"}), 500

# Import and register routes from app.py
try:
    from app import algorithm_confusion, brute_force
    
    # Register routes directly
    app.route('/algorithm-confusion', methods=['POST'])(algorithm_confusion)
    app.route('/brute-force', methods=['POST'])(brute_force)
    
    logger.info("Additional attack routes registered from app.py")
except ImportError:
    logger.warning("Could not import attack routes from app.py")

# Register advanced API if available
if has_advanced_api and register_advanced_api_fn is not None:
    register_advanced_api_fn(app)
    logger.info("Advanced API registered successfully")
else:
    logger.warning("Advanced API not available - skipping registration")

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8000))
    logger.info(f"Starting JWTKit API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])