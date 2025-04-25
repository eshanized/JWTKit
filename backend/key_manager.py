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
from db import db, KeyStore, User

# Configure logging
logger = logging.getLogger('jwtkit.key_manager')

# Define key storage location
KEY_STORE_PATH = os.environ.get('JWT_KEY_STORE', os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'keystore.json'))

class KeyManager:
    """
    Manages cryptographic keys for JWT operations, including generation,
    storage, retrieval, and format conversion.
    """
    
    def __init__(self, key_store_path: str = KEY_STORE_PATH):
        """Initialize the key manager"""
        self.key_store_path = key_store_path
        self.keys = self._load_keys()
        self.logger = logger
        
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
    
    def generate_hmac_secret(self, key_size=32):
        """
        Generate a random secret key for HMAC algorithms.
        
        Args:
            key_size: Size of the key in bytes (32 for HS256, 48 for HS384, 64 for HS512)
            
        Returns:
            Base64-encoded secret key
        """
        return base64.b64encode(os.urandom(key_size)).decode('utf-8')
    
    def generate_rsa_key_pair(self, key_size=2048):
        """
        Generate an RSA key pair for RS256/RS384/RS512/PS256/PS384/PS512 algorithms.
        
        Args:
            key_size: Size of the key in bits (2048, 3072, or 4096 recommended)
            
        Returns:
            Dictionary containing private and public keys in PEM format
        """
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
        
        return {
            'private_key': private_pem,
            'public_key': public_pem,
            'key_size': key_size,
            'key_type': 'RSA'
        }
    
    def generate_ec_key_pair(self, curve='P-256'):
        """
        Generate an EC key pair for ES256/ES384/ES512 algorithms.
        
        Args:
            curve: Elliptic curve to use (P-256, P-384, P-521)
            
        Returns:
            Dictionary containing private and public keys in PEM format
        """
        # Map curve names to cryptography curves
        curve_map = {
            'P-256': ec.SECP256R1(),
            'P-384': ec.SECP384R1(),
            'P-521': ec.SECP521R1()
        }
        
        if curve not in curve_map:
            raise ValueError(f"Unsupported curve: {curve}. Use one of: {', '.join(curve_map.keys())}")
        
        private_key = ec.generate_private_key(curve_map[curve])
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return {
            'private_key': private_pem,
            'public_key': public_pem,
            'curve': curve,
            'key_type': 'EC'
        }
    
    def generate_ed25519_key_pair(self):
        """
        Generate an Ed25519 key pair for EdDSA algorithm.
        
        Returns:
            Dictionary containing private and public keys in PEM format
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return {
            'private_key': private_pem,
            'public_key': public_pem,
            'key_type': 'EdDSA'
        }
    
    def save_key(self, name, key_type, algorithm, key_data, user_id, is_public=False):
        """
        Save a key to the database.
        
        Args:
            name: Name of the key
            key_type: Type of key (RSA, EC, HMAC, etc.)
            algorithm: Algorithm the key is used for (RS256, HS256, etc.)
            key_data: Key data (private key, public key, or secret)
            user_id: ID of the user who owns the key
            is_public: Whether the key is publicly accessible
            
        Returns:
            ID of the saved key
        """
        try:
            key = KeyStore(
                name=name,
                key_type=key_type,
                algorithm=algorithm,
                key_data=key_data,
                user_id=user_id,
                is_public=is_public
            )
            
            db.session.add(key)
            db.session.commit()
            
            self.logger.info(f"Key '{name}' saved successfully")
            return key.id
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to save key: {str(e)}")
            raise
    
    def get_key(self, key_id, user_id):
        """
        Retrieve a key from the database.
        
        Args:
            key_id: ID of the key to retrieve
            user_id: ID of the user making the request
            
        Returns:
            Key data or None if not found or not accessible
        """
        key = KeyStore.query.get(key_id)
        
        if not key:
            return None
            
        if not key.is_public and key.user_id != user_id:
            self.logger.warning(f"Unauthorized access attempt to key {key_id} by user {user_id}")
            return None
            
        return key.to_dict(include_sensitive=True)
    
    def list_user_keys(self, user_id):
        """
        List all keys for a specific user.
        
        Args:
            user_id: User ID to list keys for
            
        Returns:
            List of key metadata (without sensitive material)
        """
        keys = KeyStore.query.filter_by(user_id=user_id).all()
        return [key.to_dict(include_sensitive=False) for key in keys]
    
    def list_public_keys(self):
        """
        List all public keys available for anyone to use.
        
        Returns:
            List of public key metadata (without sensitive material)
        """
        keys = KeyStore.query.filter_by(is_public=True).all()
        return [key.to_dict(include_sensitive=False) for key in keys]
    
    def get_public_key(self, key_id):
        """
        Get a specific public key without authentication.
        
        Args:
            key_id: ID of the key
            
        Returns:
            Key details or None if not found/not public
        """
        key = KeyStore.query.get(key_id)
        
        # Only return if key is public
        if key and key.is_public:
            return key.to_dict(include_sensitive=False)
            
        return None
    
    def delete_key(self, key_id, user_id):
        """
        Delete a key from the database.
        
        Args:
            key_id: ID of the key to delete
            user_id: ID of the user making the request
            
        Returns:
            True if successful, False otherwise
        """
        key = KeyStore.query.get(key_id)
        
        if not key:
            return False
            
        if key.user_id != user_id:
            self.logger.warning(f"Unauthorized deletion attempt of key {key_id} by user {user_id}")
            return False
            
        try:
            db.session.delete(key)
            db.session.commit()
            self.logger.info(f"Key {key_id} deleted successfully")
            return True
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to delete key: {str(e)}")
            return False
            
    def generate_jwks(self, keys=None):
        """
        Generate a JWKS (JSON Web Key Set) from stored keys.
        
        Args:
            keys: List of key IDs to include, or None for all public keys
            
        Returns:
            JWKS structure as a dictionary
        """
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        import hashlib
        
        jwks = {"keys": []}
        
        if keys:
            query = KeyStore.query.filter(KeyStore.id.in_(keys))
        else:
            query = KeyStore.query.filter(KeyStore.is_public == True)
            
        for key in query.all():
            # Skip HMAC keys for JWKS
            if key.key_type == 'HMAC':
                continue
                
            # Process asymmetric keys
            jwk = {}
            
            if key.key_type == 'RSA':
                # Load the public key
                public_key = serialization.load_pem_public_key(key.key_data.encode())
                if not isinstance(public_key, rsa.RSAPublicKey):
                    continue
                    
                # Get the key components
                numbers = public_key.public_numbers()
                
                # Add RSA-specific parameters
                jwk.update({
                    "kty": "RSA",
                    "n": base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "e": base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('=')
                })
                
            elif key.key_type == 'EC':
                # Load the public key
                public_key = serialization.load_pem_public_key(key.key_data.encode())
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    continue
                    
                # Get the curve name
                curve_name = public_key.curve.name
                
                # Map to JWK curve names
                curve_map = {
                    'secp256r1': 'P-256',
                    'secp384r1': 'P-384',
                    'secp521r1': 'P-521'
                }
                
                jwk_curve = curve_map.get(curve_name)
                if not jwk_curve:
                    continue
                    
                # Convert point to x,y coordinates
                numbers = public_key.public_numbers()
                
                # Add EC-specific parameters
                jwk.update({
                    "kty": "EC",
                    "crv": jwk_curve,
                    "x": base64.urlsafe_b64encode(numbers.x.to_bytes((numbers.curve.key_size + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "y": base64.urlsafe_b64encode(numbers.y.to_bytes((numbers.curve.key_size + 7) // 8, byteorder='big')).decode('utf-8').rstrip('=')
                })
                
            else:
                # Skip unsupported key types
                continue
                
            # Add common fields
            kid = hashlib.sha256(key.key_data.encode()).hexdigest()[:16]
            jwk.update({
                "kid": kid,
                "use": "sig",
                "alg": key.algorithm
            })
            
            jwks["keys"].append(jwk)
            
        return jwks

    def export_jwks(self, include_private=False):
        """
        Export keys in JWKS format.
        :param include_private: Whether to include private keys in the export.
        :return: A dictionary representing the JWKS.
        """
        jwks = {"keys": []}
        for key in self.list_user_keys():
            jwk = {
                "kid": key.get("kid", ""),
                "kty": key.get("kty", ""),
                "alg": key.get("alg", ""),
                "use": "sig",
                "key_ops": ["verify"] if not include_private else ["sign", "verify"],
            }
            
            if key.get("kty") in ["RSA", "EC", "OKP"]:
                if "public_key" in key:
                    jwk["x5c"] = [key["public_key"]]
                if include_private and "private_key" in key:
                    jwk["d"] = key["private_key"]
            elif key.get("kty") == "HMAC":
                if "k" in key:
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