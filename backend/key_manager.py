"""
JWTKit Key Manager

This module handles cryptographic key generation, storage, rotation and JWKS endpoints.
"""

import os
import json
import time
import uuid
import base64
import logging
import hashlib
from typing import Dict, List, Optional, Tuple, Union, Any
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256

# Configure logging
logger = logging.getLogger('jwtkit.key_manager')

# Define key storage location
KEY_STORE_PATH = os.environ.get('JWT_KEY_STORE', os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'keystore.json'))

class KeyManager:
    """Manages cryptographic keys for JWT signing and verification"""
    
    def __init__(self, key_store_path: str = KEY_STORE_PATH):
        """Initialize the key manager"""
        self.key_store_path = key_store_path
        self.keys = self._load_keys()
        
    def _load_keys(self) -> Dict[str, Any]:
        """Load keys from storage"""
        try:
            if os.path.exists(self.key_store_path):
                with open(self.key_store_path, 'r') as f:
                    return json.load(f)
            else:
                # Initialize with empty key store
                keys = {
                    "keys": [],
                    "meta": {
                        "created_at": datetime.utcnow().isoformat(),
                        "updated_at": datetime.utcnow().isoformat()
                    }
                }
                self._save_keys(keys)
                return keys
        except Exception as e:
            logger.error(f"Error loading keys: {str(e)}")
            # Return empty key store on error
            return {
                "keys": [],
                "meta": {
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
            }
    
    def _save_keys(self, keys: Optional[Dict[str, Any]] = None) -> bool:
        """Save keys to storage"""
        try:
            if keys is None:
                keys = self.keys
                
            # Update metadata
            keys["meta"]["updated_at"] = datetime.utcnow().isoformat()
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.key_store_path), exist_ok=True)
            
            with open(self.key_store_path, 'w') as f:
                json.dump(keys, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving keys: {str(e)}")
            return False
    
    def generate_key(self, key_type: str, algorithm: str, **kwargs) -> Dict[str, Any]:
        """Generate a new key
        
        Args:
            key_type: Type of key to generate (hmac, rsa, ec, ed25519)
            algorithm: JWT algorithm to use with this key
            **kwargs: Additional parameters for key generation
                - bits: For HMAC keys, length in bits
                - key_size: For RSA keys, key size in bits
                - curve: For EC keys, curve name (P-256, P-384, P-521)
        
        Returns:
            Dict containing key information
        """
        key_id = str(uuid.uuid4())
        now = datetime.utcnow()
        
        key_info = {
            "kid": key_id,
            "kty": key_type.upper(),
            "alg": algorithm,
            "use": "sig",
            "created_at": now.isoformat(),
            "active": True
        }
        
        # Generate key based on type
        if key_type.lower() == "hmac":
            # Default to 256 bits if not specified
            bits = kwargs.get("bits", 256)
            key_data = os.urandom(bits // 8)
            key_info["k"] = base64.urlsafe_b64encode(key_data).decode('utf-8').rstrip('=')
            key_info["bits"] = bits
            
        elif key_type.lower() == "rsa":
            # Default to 2048 bits if not specified
            key_size = kwargs.get("key_size", 2048)
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Get key components
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Store key information
            key_info["key_size"] = key_size
            key_info["private_key"] = private_pem.decode('utf-8')
            key_info["public_key"] = public_pem.decode('utf-8')
            
            # Add JWK components
            numbers = public_key.public_numbers()
            e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder='big')
            n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder='big')
            
            key_info["e"] = base64.urlsafe_b64encode(e).decode('utf-8').rstrip('=')
            key_info["n"] = base64.urlsafe_b64encode(n).decode('utf-8').rstrip('=')
            
        elif key_type.lower() == "ec":
            # Default to P-256 if not specified
            curve_name = kwargs.get("curve", "P-256")
            
            # Map curve name to the cryptography curve object
            curves = {
                "P-256": ec.SECP256R1(),
                "P-384": ec.SECP384R1(),
                "P-521": ec.SECP521R1()
            }
            
            if curve_name not in curves:
                raise ValueError(f"Unsupported curve: {curve_name}")
                
            curve = curves[curve_name]
            private_key = ec.generate_private_key(curve, default_backend())
            
            # Get key components
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Store key information
            key_info["curve"] = curve_name
            key_info["private_key"] = private_pem.decode('utf-8')
            key_info["public_key"] = public_pem.decode('utf-8')
            
            # Add JWK components
            numbers = public_key.public_numbers()
            x = numbers.x.to_bytes((numbers.curve.key_size + 7) // 8, byteorder='big')
            y = numbers.y.to_bytes((numbers.curve.key_size + 7) // 8, byteorder='big')
            
            key_info["crv"] = curve_name
            key_info["x"] = base64.urlsafe_b64encode(x).decode('utf-8').rstrip('=')
            key_info["y"] = base64.urlsafe_b64encode(y).decode('utf-8').rstrip('=')
            
        elif key_type.lower() == "ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
            
            # Get key components
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Store key information
            key_info["private_key"] = private_pem.decode('utf-8')
            key_info["public_key"] = public_pem.decode('utf-8')
            
            # Add JWK components
            key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            key_info["crv"] = "Ed25519"
            key_info["x"] = base64.urlsafe_b64encode(key_bytes).decode('utf-8').rstrip('=')
            
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Add key to store
        self.keys["keys"].append(key_info)
        self._save_keys()
        
        # Create a safe version of the key info (without private keys)
        safe_key_info = self._filter_sensitive_data(key_info)
        
        return safe_key_info
    
    def _filter_sensitive_data(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from key info for external use"""
        filtered = key_data.copy()
        
        # Remove private key material
        if "private_key" in filtered:
            del filtered["private_key"]
            
        # For HMAC keys, must not expose the secret
        if filtered.get("kty") == "HMAC" and "k" in filtered:
            # Replace actual key with a placeholder
            filtered["k"] = "[FILTERED]"
            
        return filtered
    
    def list_keys(self, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """List all keys"""
        keys = self.keys.get("keys", [])
        
        # Filter inactive keys if requested
        if not include_inactive:
            keys = [k for k in keys if k.get("active", True)]
            
        # Filter sensitive data
        return [self._filter_sensitive_data(k) for k in keys]
    
    def get_key(self, kid: str) -> Optional[Dict[str, Any]]:
        """Get a specific key by ID"""
        for key in self.keys.get("keys", []):
            if key.get("kid") == kid:
                return key
        return None
    
    def get_key_for_algorithm(self, algorithm: str, active_only: bool = True) -> Optional[Dict[str, Any]]:
        """Get the most recent key for a specific algorithm"""
        matching_keys = []
        
        for key in self.keys.get("keys", []):
            if key.get("alg") == algorithm:
                if active_only and not key.get("active", True):
                    continue
                matching_keys.append(key)
                
        if not matching_keys:
            return None
            
        # Sort by creation time (newest first)
        matching_keys.sort(key=lambda k: k.get("created_at", ""), reverse=True)
        return matching_keys[0]
    
    def rotate_keys(self, algorithm: str) -> Dict[str, Any]:
        """Rotate keys for a specific algorithm
        
        This deactivates all existing keys for the algorithm and generates a new one
        """
        # Find existing keys for this algorithm
        for key in self.keys.get("keys", []):
            if key.get("alg") == algorithm and key.get("active", True):
                # Deactivate the key
                key["active"] = False
                key["deactivated_at"] = datetime.utcnow().isoformat()
                
        # Get parameters from the most recent key
        existing_key = self.get_key_for_algorithm(algorithm, active_only=False)
        
        params = {}
        if existing_key:
            key_type = existing_key.get("kty", "").lower()
            
            if key_type == "hmac":
                params["bits"] = existing_key.get("bits", 256)
            elif key_type == "rsa":
                params["key_size"] = existing_key.get("key_size", 2048)
            elif key_type == "ec":
                params["curve"] = existing_key.get("curve", "P-256")
        else:
            # Determine key type from algorithm
            if algorithm.startswith("HS"):
                key_type = "hmac"
                params["bits"] = int(algorithm[2:])
            elif algorithm.startswith("RS") or algorithm.startswith("PS"):
                key_type = "rsa"
                params["key_size"] = 2048
            elif algorithm.startswith("ES"):
                key_type = "ec"
                bit_size = algorithm[2:]
                curve_map = {
                    "256": "P-256",
                    "384": "P-384",
                    "512": "P-521"  # P-521 for ES512
                }
                params["curve"] = curve_map.get(bit_size, "P-256")
            elif algorithm == "EdDSA":
                key_type = "ed25519"
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
                
        # Generate a new key
        new_key = self.generate_key(key_type, algorithm, **params)
        
        # Save changes
        self._save_keys()
        
        return new_key
    
    def delete_key(self, kid: str) -> bool:
        """Delete a key permanently"""
        for i, key in enumerate(self.keys.get("keys", [])):
            if key.get("kid") == kid:
                self.keys["keys"].pop(i)
                self._save_keys()
                return True
        return False
    
    def get_jwks(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get JWKS (JSON Web Key Set) containing public keys"""
        jwks_keys = []
        
        for key in self.keys.get("keys", []):
            if not key.get("active", True):
                continue
                
            jwk = {
                "kid": key.get("kid"),
                "kty": key.get("kty"),
                "use": key.get("use", "sig"),
                "alg": key.get("alg")
            }
            
            # Add key-specific fields
            if key.get("kty") == "RSA":
                jwk["e"] = key.get("e")
                jwk["n"] = key.get("n")
            elif key.get("kty") == "EC":
                jwk["crv"] = key.get("crv")
                jwk["x"] = key.get("x")
                jwk["y"] = key.get("y")
            elif key.get("kty") == "OKP":  # Ed25519 keys
                jwk["crv"] = key.get("crv", "Ed25519")
                jwk["x"] = key.get("x")
                
            # HMAC keys are not included in public JWKS
            # as they're symmetric and should remain private
            if key.get("kty") != "HMAC":
                jwks_keys.append(jwk)
        
        return {"keys": jwks_keys}

    def export_jwks(self, include_private=False):
        """
        Export keys in JWKS format.
        :param include_private: Whether to include private keys in the export.
        :return: A dictionary representing the JWKS.
        """
        jwks = {"keys": []}
        for key in self.list_keys():
            jwk = {
                "kid": key["kid"],
                "kty": key["type"],
                "alg": key["alg"],
                "use": "sig",
                "key_ops": ["verify"] if not include_private else ["sign", "verify"],
            }
            if key["type"] in ["rsa", "ec", "ed25519"]:
                jwk["x5c"] = [key["public_key"]]
                if include_private:
                    jwk["d"] = key["private_key"]
            elif key["type"] == "hmac":
                jwk["k"] = key["k"]
            jwks["keys"].append(jwk)
        return jwks


# Singleton instance
_instance = None

def get_key_manager() -> KeyManager:
    """Get or create the key manager instance"""
    global _instance
    if _instance is None:
        _instance = KeyManager()
    return _instance