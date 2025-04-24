"""
Advanced API endpoints for JWTKit

This module extends the basic API with more sophisticated endpoints:
- Key management
- JWT attack simulation
- Token auditing
- JWKS endpoint
"""

from flask import Flask, request, jsonify, Blueprint
import json
import base64
import os
from datetime import datetime, timedelta
import logging

# Import JWT libraries with fallback
try:
    import jwt
except ImportError:
    print("Error: PyJWT not installed. Run: pip install pyjwt")
    jwt = None

# Import our custom modules
try:
    # type: ignore
    from key_manager import get_key_manager
    from attack_simulator import JWTSecurityTester as ExternalJWTSecurityTester
    has_advanced_modules = True
except ImportError:
    print("Warning: Advanced modules not found. Some features will be disabled.")
    has_advanced_modules = False
    
    # Define fallback classes to prevent errors
    class KeyManager:
        """Fallback KeyManager that returns None for all operations"""
        def export_jwks(self, include_private=False):
            return {"keys": []}
            
        def list_keys(self, include_inactive=False):
            return []
            
        def get_key(self, kid):
            return None
            
        def get_key_for_algorithm(self, algorithm, active_only=True):
            return None
            
        def generate_key(self, key_type, algorithm, **kwargs):
            return {}
            
        def rotate_keys(self, algorithm):
            return {}
    
    def get_key_manager():
        return KeyManager()
    
    # Use proper type annotation for the security tester
    class JWTSecurityTester:
        @staticmethod
        def none_algorithm_attack(token):
            return {"success": False, "error": "Attack simulator not available"}
            
        @staticmethod
        def algorithm_confusion_attack(token, public_key):
            return {"success": False, "error": "Attack simulator not available"}
            
        @staticmethod
        def signature_removal_attack(token):
            return {"success": False, "error": "Attack simulator not available"}
            
        @staticmethod
        def key_injection_attack(token):
            return {"success": False, "error": "Attack simulator not available"}
            
        @staticmethod
        def kid_sql_injection_attack(token):
            return {"success": False, "error": "Attack simulator not available"}
            
        @staticmethod
        def kid_directory_traversal_attack(token):
            return {"success": False, "error": "Attack simulator not available"}
            
        @staticmethod
        def brute_force_secret(token, wordlist):
            return {"success": False, "error": "Attack simulator not available"}
            
        @staticmethod
        def run_all_attacks(token, public_key=None, wordlist=None):
            return {"success": False, "error": "Attack simulator not available"}
    
    # Alias for type compatibility
    ExternalJWTSecurityTester = JWTSecurityTester

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('advanced_api')

# Create Blueprint for advanced API endpoints
advanced_api = Blueprint('advanced_api', __name__)

@advanced_api.route('/health', methods=['GET'])
def health_check():
    """Health check for advanced API endpoints"""
    features_available = {
        "key_management": has_advanced_modules,
        "attack_simulation": has_advanced_modules,
        "jwt_library": jwt is not None
    }
    
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "features_available": features_available
    })

@advanced_api.route('/jwks.json', methods=['GET'])
def jwks_endpoint():
    """
    JSON Web Key Set (JWKS) endpoint.
    Returns public keys in JWKS format for token verification.
    """
    if not has_advanced_modules:
        return jsonify({"error": "Key management module not available"}), 501
    
    try:
        key_manager = get_key_manager()
        jwks = key_manager.export_jwks(include_private=False)
        return jsonify(jwks)
    except Exception as e:
        logger.error(f"Error in JWKS endpoint: {str(e)}")
        return jsonify({"error": f"Failed to generate JWKS: {str(e)}"}), 500

@advanced_api.route('/keys', methods=['GET'])
def list_keys():
    """List all active keys"""
    if not has_advanced_modules:
        return jsonify({"error": "Key management module not available"}), 501
    
    try:
        include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
        key_manager = get_key_manager()
        keys = key_manager.list_keys(include_inactive=include_inactive)
        
        # Filter out sensitive information for API response
        safe_keys = []
        for key in keys:
            safe_key = {
                "kid": key.get("kid"),
                "alg": key.get("alg"),
                "type": key.get("kty", "").lower(),  # Return lowercase type for compatibility
                "created_at": key.get("created_at"),
                "expires_at": key.get("expires_at")
            }
            
            # Include public key for asymmetric keys
            if key.get("kty") in ["RSA", "EC", "OKP"]:
                safe_key["public_key"] = key.get("public_key")
                
            safe_keys.append(safe_key)
        
        return jsonify({"keys": safe_keys})
    except Exception as e:
        logger.error(f"Error listing keys: {str(e)}")
        return jsonify({"error": f"Failed to list keys: {str(e)}"}), 500

@advanced_api.route('/keys', methods=['POST'])
def generate_key():
    """Generate a new key for JWT signing"""
    if not has_advanced_modules:
        return jsonify({"error": "Key management module not available"}), 501
    
    data = request.json or {}
    key_type = data.get('type', 'rsa')
    algorithm = data.get('algorithm')
    
    try:
        key_manager = get_key_manager()
        
        if key_type == 'hmac':
            bits = int(data.get('bits', 256))
            algorithm = algorithm or "HS256"
            key_data = key_manager.generate_key(key_type='hmac', algorithm=algorithm, bits=bits)
        elif key_type == 'rsa':
            key_size = int(data.get('key_size', 2048))
            algorithm = algorithm or "RS256"
            key_data = key_manager.generate_key(key_type='rsa', key_size=key_size, algorithm=algorithm)
        elif key_type == 'ec':
            curve = data.get('curve', 'P-256')
            algorithm = algorithm or "ES256"
            key_data = key_manager.generate_key(key_type='ec', curve=curve, algorithm=algorithm)
        elif key_type == 'ed25519':
            algorithm = "EdDSA"
            key_data = key_manager.generate_key(key_type='ed25519', algorithm=algorithm)
        else:
            return jsonify({"error": f"Unsupported key type: {key_type}"}), 400
        
        # Filter out sensitive information for API response
        safe_key = {
            "kid": key_data.get("kid"),
            "alg": key_data.get("alg"),
            "type": key_data.get("type"),
            "created_at": key_data.get("created_at"),
            "expires_at": key_data.get("expires_at")
        }
        
        # Include public key for asymmetric keys
        if key_type in ["rsa", "ec", "ed25519"]:
            safe_key["public_key"] = key_data.get("public_key")
        
        return jsonify(safe_key)
    except Exception as e:
        logger.error(f"Error generating key: {str(e)}")
        return jsonify({"error": f"Failed to generate key: {str(e)}"}), 500

@advanced_api.route('/keys/rotate', methods=['POST'])
def rotate_key():
    """Rotate a key for a specific algorithm"""
    if not has_advanced_modules:
        return jsonify({"error": "Key management module not available"}), 501
    
    data = request.json or {}
    algorithm = data.get('algorithm')
    
    if not algorithm:
        return jsonify({"error": "Algorithm is required"}), 400
    
    try:
        key_manager = get_key_manager()
        new_key = key_manager.rotate_keys(algorithm)
        
        # Filter out sensitive information for API response
        safe_key = {
            "kid": new_key.get("kid"),
            "alg": new_key.get("alg"),
            "type": new_key.get("type"),
            "created_at": new_key.get("created_at"),
            "expires_at": new_key.get("expires_at")
        }
        
        # Include public key for asymmetric keys
        if new_key.get("type") in ["rsa", "ec", "ed25519"]:
            safe_key["public_key"] = new_key.get("public_key")
        
        return jsonify({
            "message": f"Successfully rotated key for {algorithm}",
            "new_key": safe_key
        })
    except Exception as e:
        logger.error(f"Error rotating key: {str(e)}")
        return jsonify({"error": f"Failed to rotate key: {str(e)}"}), 500

@advanced_api.route('/sign', methods=['POST'])
def sign_token():
    """Sign a payload with a managed key"""
    if not has_advanced_modules:
        return jsonify({"error": "Key management module not available"}), 501

    if jwt is None:
        return jsonify({"error": "PyJWT library not available"}), 501

    data = request.json or {}
    payload = data.get('payload')
    algorithm = data.get('algorithm', 'RS256')
    expiration = data.get('expiration_seconds')
    kid = data.get('kid')

    if not payload:
        return jsonify({"error": "Payload is required"}), 400

    try:
        key_manager = get_key_manager()

        # If kid is specified, use that key
        if kid:
            key_data = key_manager.get_key(kid)
            if not key_data:
                return jsonify({"error": f"Key with ID {kid} not found"}), 404
        else:
            # Otherwise use the active key for the algorithm
            key_data = key_manager.get_key_for_algorithm(algorithm)
            if not key_data:
                return jsonify({"error": f"No active key found for algorithm {algorithm}"}), 404

        # Add standard claims if not present
        if 'iat' not in payload:
            payload['iat'] = int(datetime.utcnow().timestamp())

        if expiration and 'exp' not in payload:
            payload['exp'] = int((datetime.utcnow() + timedelta(seconds=expiration)).timestamp())

        # Get the key material and convert to string if needed
        if key_data['type'] == 'hmac':
            key = base64.b64decode(key_data['k']).decode('utf-8')  # Convert bytes to string
        else:
            key = key_data['private_key']

        # Sign the token
        headers = {'kid': key_data['kid']}
        token = jwt.encode(payload, key, algorithm=key_data['alg'], headers=headers)
        # PyJWT >=2.0 returns str, <2.0 returns bytes
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return jsonify({
            "token": token,
            "algorithm": key_data['alg'],
            "kid": key_data['kid']
        })
    except Exception as e:
        logger.error(f"Error signing token: {str(e)}")
        return jsonify({"error": f"Failed to sign token: {str(e)}"}), 500

@advanced_api.route('/verify-managed', methods=['POST'])
def verify_managed_token():
    """Verify a token using managed keys"""
    if not has_advanced_modules:
        return jsonify({"error": "Key management module not available"}), 501

    if jwt is None:
        return jsonify({"error": "PyJWT library not available"}), 501

    data = request.json or {}
    token = data.get('token')

    if not token:
        return jsonify({"error": "Token is required"}), 400

    try:
        # Decode the token header without verification to get kid/alg
        parts = token.split('.')
        if len(parts) != 3:
            return jsonify({"error": "Invalid token format"}), 400

        header_json = base64.urlsafe_b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        header = json.loads(header_json)

        kid = header.get('kid')
        alg = header.get('alg')

        if not kid:
            return jsonify({"error": "Token does not contain a key ID (kid)"}), 400

        # Get the key from our key manager
        key_manager = get_key_manager()
        key_data = key_manager.get_key(kid)

        if not key_data:
            return jsonify({
                "valid": False,
                "error": f"Key with ID {kid} not found in key store"
            })

        # Initialize verification result in case we encounter errors
        verification_result = {
            "valid": False,
            "error": "Unknown error occurred"
        }

        # Handle key based on type and convert to string if needed
        key_type = key_data.get('kty', '').upper()
        if key_type == 'HMAC':
            key = base64.b64decode(key_data['k'])
            # Ensure key is string for jwt.decode
            if isinstance(key, bytes):
                key = key.decode('utf-8')
        elif key_type in ['RSA', 'EC', 'OKP']:
            key = key_data['public_key']
        else:
            key = None
            verification_result = {
                "valid": False,
                "error": f"Unsupported key type: {key_type}",
                "note": "Cannot verify token with this key type"
            }
            
        # Try to verify
        if key is not None:
            if jwt is None:
                verification_result = {
                    "valid": False,
                    "error": "PyJWT library not available",
                    "note": "Cannot verify token without PyJWT library"
                }
            else:
                try:
                    decoded = jwt.decode(token, key, algorithms=[header.get('alg')])
                    
                    verification_result = {
                        "valid": True,
                        "payload": decoded,
                        "note": "Token verified with a key from the key store",
                        "key_info": {
                            "kid": key_data.get('kid', ''),
                            "alg": key_data.get('alg', ''),
                            "type": key_type.lower()
                        }
                    }
                except Exception as e:
                    verification_result = {
                        "valid": False,
                        "error": str(e),
                        "note": "Failed to verify token with the found key"
                    }

        return jsonify(verification_result)
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

@advanced_api.route('/attack-simulation', methods=['POST'])
def simulate_attacks():
    """
    Simulate various JWT attacks on a token.
    """
    if not has_advanced_modules:
        return jsonify({"error": "Attack simulation module not available"}), 501
    
    data = request.json or {}
    token = data.get('token')
    public_key = data.get('public_key')
    attack_type = data.get('attack_type')
    wordlist = data.get('wordlist')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        # If a specific attack is requested
        if attack_type:
            result = None
            
            if attack_type == 'none_algorithm':
                result = ExternalJWTSecurityTester.none_algorithm_attack(token)
            elif attack_type == 'algorithm_confusion':
                if not public_key:
                    return jsonify({"error": "Public key is required for algorithm confusion attack"}), 400
                result = ExternalJWTSecurityTester.algorithm_confusion_attack(token, public_key)
            elif attack_type == 'key_injection':
                result = ExternalJWTSecurityTester.key_injection_attack(token)
            elif attack_type == 'signature_removal':
                result = ExternalJWTSecurityTester.signature_removal_attack(token)
            elif attack_type == 'kid_sql_injection':
                result = ExternalJWTSecurityTester.kid_sql_injection_attack(token)
            elif attack_type == 'kid_directory_traversal':
                result = ExternalJWTSecurityTester.kid_directory_traversal_attack(token)
            elif attack_type == 'brute_force':
                if not wordlist:
                    # Load default wordlist if none provided
                    try:
                        with open('wordlists/common_jwt_secrets.txt', 'r') as f:
                            wordlist = [line.strip() for line in f]
                    except FileNotFoundError:
                        return jsonify({"error": "Wordlist is required for brute force attack"}), 400
                result = ExternalJWTSecurityTester.brute_force_secret(token, wordlist)
            else:
                return jsonify({"error": f"Unsupported attack type: {attack_type}"}), 400
            
            return jsonify(result)
        else:
            # Run all attacks if no specific attack is requested
            # Load default wordlist for brute force
            if not wordlist:
                try:
                    with open('wordlists/common_jwt_secrets.txt', 'r') as f:
                        wordlist = [line.strip() for line in f]
                except FileNotFoundError:
                    wordlist = None
                    
            result = ExternalJWTSecurityTester.run_all_attacks(token, public_key, wordlist)
            return jsonify(result)
            
    except Exception as e:
        logger.error(f"Error in attack simulation: {str(e)}")
        return jsonify({"error": f"Attack simulation failed: {str(e)}"}), 500

@advanced_api.route('/audit', methods=['POST'])
def audit_token():
    """
    Comprehensive JWT token audit:
    - Decode and parse
    - Check for vulnerabilities
    - Attempt known attacks
    - Verify signature if possible
    """
    if not has_advanced_modules:
        return jsonify({"error": "Advanced modules not available"}), 501

    data = request.json or {}
    token = data.get('token')

    if not token:
        return jsonify({"error": "Token is required"}), 400

    try:
        # 1. Decode the token
        parts = token.split('.')
        if len(parts) != 3:
            return jsonify({"error": "Invalid token format"}), 400

        header_json = base64.urlsafe_b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8')
        payload_json = base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8')

        header = json.loads(header_json)
        payload = json.loads(payload_json)

        # 2. Check for basic vulnerabilities
        vulnerabilities = []

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
            if exp_time < datetime.utcnow():
                vulnerabilities.append({
                    "severity": "info",
                    "issue": "Expired Token",
                    "description": f"Token expired on {exp_time.isoformat()}"
                })
            elif exp_time > datetime.utcnow() + timedelta(days=30):
                vulnerabilities.append({
                    "severity": "low",
                    "issue": "Long Expiration",
                    "description": "Token has a very long expiration time (>30 days)."
                })

        # 3. Run selected attacks
        attack_results = {}

        # Always try none algorithm attack
        attack_results["none_algorithm"] = ExternalJWTSecurityTester.none_algorithm_attack(token)

        # Try algorithm confusion only for RS256
        if header.get('alg') == 'RS256':
            # We don't have the public key, but we'll include this for completeness
            attack_results["algorithm_confusion"] = {
                "success": False,
                "error": "Public key is required for algorithm confusion attack",
                "note": "This attack is applicable to this token but requires the RSA public key."
            }

        # Try signature removal
        attack_results["signature_removal"] = ExternalJWTSecurityTester.signature_removal_attack(token)

        # 4. Try to verify with managed keys if there's a kid
        verification_result = None
        kid = header.get('kid')

        if kid:
            try:
                key_manager = get_key_manager()
                key_data = key_manager.get_key(kid)

                if key_data and key_data['alg'] == header.get('alg'):
                    # Get the appropriate key material
                    key_type = key_data.get('kty', '').upper()
                    if key_type == 'HMAC':
                        key = base64.b64decode(key_data['k'])
                        # Ensure key is string for jwt.decode
                        if isinstance(key, bytes):
                            key = key.decode('utf-8')
                    elif key_type in ['RSA', 'EC', 'OKP']:
                        key = key_data['public_key']
                    else:
                        key = None
                        verification_result = {
                            "valid": False,
                            "error": f"Unsupported key type: {key_type}",
                            "note": "Cannot verify token with this key type"
                        }
                        
                    # Try to verify
                    if key is not None:
                        if jwt is None:
                            verification_result = {
                                "valid": False,
                                "error": "PyJWT library not available",
                                "note": "Cannot verify token without PyJWT library"
                            }
                        else:
                            try:
                                decoded = jwt.decode(token, key, algorithms=[header.get('alg')])
                                
                                verification_result = {
                                    "valid": True,
                                    "payload": decoded,
                                    "note": "Token verified with a key from the key store"
                                }
                            except Exception as e:
                                verification_result = {
                                    "valid": False,
                                    "error": str(e),
                                    "note": "Failed to verify token with the found key"
                                }
                else:
                    verification_result = {
                        "valid": False,
                        "error": "Key not found or algorithm mismatch",
                        "note": "Token has a kid but no matching key found in key store"
                    }
            except Exception as e:
                verification_result = {
                    "valid": False,
                    "error": str(e),
                    "note": "Error occurred during verification attempt"
                }

        # 5. Compile the audit report
        successful_attacks = [k for k, v in attack_results.items() if v.get("success", False)]
        vulnerability_score = len(vulnerabilities) * 10 + len(successful_attacks) * 15

        # Cap the score at 100
        vulnerability_score = min(vulnerability_score, 100)

        audit_report = {
            "token_info": {
                "header": header,
                "payload": payload,
                "signature": parts[2]
            },
            "vulnerabilities": vulnerabilities,
            "attacks": {
                "successful": successful_attacks,
                "results": attack_results
            },
            "verification": verification_result,
            "risk_score": vulnerability_score,
            "risk_level": "Critical" if vulnerability_score > 80 else
                         "High" if vulnerability_score > 60 else
                         "Medium" if vulnerability_score > 40 else
                         "Low" if vulnerability_score > 20 else
                         "Minimal",
            "recommendations": [
                "Use asymmetric algorithms like RS256 or ES256 when possible",
                "Always include expiration time (exp) in tokens",
                "Validate issuer and audience claims",
                "Implement proper key rotation",
                "Use strong, random keys for HMAC algorithms",
                "Validate token algorithm and type before verification"
            ]
        }

        return jsonify(audit_report)

    except Exception as e:
        logger.error(f"Error in token audit: {str(e)}")
        return jsonify({"error": f"Token audit failed: {str(e)}"}), 500

def register_advanced_api(app):
    """Register the advanced API Blueprint with a Flask app"""
    app.register_blueprint(advanced_api, url_prefix='/api/v1')
    logger.info("Advanced API endpoints registered"   
                
                
                
                
                
                
                
                )