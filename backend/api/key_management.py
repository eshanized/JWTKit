from flask import request, jsonify, g
from flask_jwt_extended import get_jwt_identity
from db import User
from jwt_optional import jwt_optional, get_current_user, is_authenticated

def register_key_routes(app, limiter):
    """
    Register routes for key management.
    
    Routes include:
    - List keys
    - Create a key
    - Delete a key
    - Generate RSA key pairs
    - Generate EC key pairs
    - Generate HMAC secrets
    - Export JWKS
    """
    
    @app.route('/api/keys', methods=['GET'])
    @jwt_optional
    def get_keys():
        """Get all keys for the current user"""
        if is_authenticated():
            # Authenticated user - get their keys
            current_user = get_jwt_identity()
            user = User.query.filter_by(username=current_user).first()
            
            if not user:
                return jsonify({"error": "User not found"}), 404
                
            # Get user's key manager
            key_manager = g.key_manager
            keys = key_manager.list_user_keys(user.id)
            
            return jsonify({"keys": keys})
        else:
            # Guest user - show only public keys
            key_manager = g.key_manager
            keys = key_manager.list_public_keys()
            
            return jsonify({
                "keys": keys,
                "message": "Showing public keys only. Log in to manage your own keys."
            })
    
    @app.route('/api/keys', methods=['POST'])
    @jwt_optional
    def create_key():
        """Save a key to the database"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        
        if not is_authenticated():
            # For guests, offer temporary keys that aren't saved
            name = data.get('name', '')
            key_type = data.get('key_type', '')
            algorithm = data.get('algorithm', '')
            key_data = data.get('key_data', '')
            
            if not all([name, key_type, algorithm, key_data]):
                return jsonify({"error": "Missing required fields"}), 400
                
            return jsonify({
                "message": "Key created in temporary storage. Log in to save keys permanently.",
                "key": {
                    "name": name,
                    "key_type": key_type,
                    "algorithm": algorithm,
                    "key_data": key_data,
                    "is_temporary": True
                }
            })
            
        # Authenticated user flow
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        name = data.get('name', '')
        key_type = data.get('key_type', '')
        algorithm = data.get('algorithm', '')
        key_data = data.get('key_data', '')
        is_public = data.get('is_public', False)
        
        if not all([name, key_type, algorithm, key_data]):
            return jsonify({"error": "Missing required fields"}), 400
            
        # Get user's key manager
        key_manager = g.key_manager
        result = key_manager.save_key(
            name=name,
            key_type=key_type,
            algorithm=algorithm,
            key_data=key_data,
            user_id=user.id,
            is_public=is_public
        )
        
        if isinstance(result, dict) and "error" in result:
            return jsonify({"error": result["error"]}), 400
            
        # Log the activity
        g.audit_manager.log_event(
            event_type="key_created",
            username=current_user,
            details=f"Key created: {name} ({key_type}/{algorithm})"
        )
        
        return jsonify({
            "message": "Key created successfully",
            "key_id": result
        })
    
    @app.route('/api/keys/<int:key_id>', methods=['GET'])
    @jwt_optional
    def get_key(key_id):
        """Get a specific key"""
        key_manager = g.key_manager
        
        if is_authenticated():
            # Authenticated user - get their key
            current_user = get_jwt_identity()
            user = User.query.filter_by(username=current_user).first()
            
            if not user:
                return jsonify({"error": "User not found"}), 404
                
            key = key_manager.get_key(key_id, user.id)
        else:
            # Guest user - can only access public keys
            key = key_manager.get_public_key(key_id)
        
        if not key:
            return jsonify({"error": "Key not found or access denied"}), 404
            
        return jsonify({"key": key})
    
    @app.route('/api/keys/<int:key_id>', methods=['DELETE'])
    @jwt_optional
    def delete_key(key_id):
        """Delete a key"""
        if not is_authenticated():
            return jsonify({
                "error": "Authentication required",
                "message": "You must be logged in to delete keys"
            }), 401
            
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Get user's key manager
        key_manager = g.key_manager
        result = key_manager.delete_key(key_id, user.id)
        
        if isinstance(result, dict) and "error" in result:
            return jsonify({"error": result["error"]}), 400
            
        # Log the activity
        g.audit_manager.log_event(
            event_type="key_deleted",
            username=current_user,
            details=f"Key deleted: ID {key_id}"
        )
        
        return jsonify({
            "message": "Key deleted successfully"
        })
    
    @app.route('/api/keys/generate-rsa', methods=['POST'])
    @jwt_optional
    @limiter.limit("10/minute")
    def generate_rsa_key():
        """Generate a new RSA key pair"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        
        key_size = data.get('key_size', 2048)
        name = data.get('name', 'RSA Key')
        is_public = data.get('is_public', False)
        
        # Generate the key
        key_manager = g.key_manager
        key_pair = key_manager.generate_rsa_key_pair(key_size)
        
        if not is_authenticated():
            # For guests, return the key pair but don't save it
            return jsonify({
                "message": "RSA key pair generated successfully (temporary)",
                "key_pair": key_pair,
                "note": "Log in to save keys permanently"
            })
        
        # Authenticated user flow - save the key
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Save the key to the database
        key_id = key_manager.save_key(
            name=name,
            key_type="RSA",
            algorithm="RS256",
            key_data=key_pair["private_key"],
            user_id=user.id,
            is_public=is_public
        )
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="key_generated",
            username=current_user,
            details=f"RSA key pair generated ({key_size} bits)"
        )
        
        return jsonify({
            "message": "RSA key pair generated successfully",
            "key_id": key_id,
            "public_key": key_pair["public_key"]
        })
    
    @app.route('/api/keys/generate-ec', methods=['POST'])
    @jwt_optional
    @limiter.limit("10/minute")
    def generate_ec_key():
        """Generate a new EC key pair"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        
        curve = data.get('curve', 'P-256')
        name = data.get('name', 'EC Key')
        is_public = data.get('is_public', False)
        
        # Generate the key
        key_manager = g.key_manager
        key_pair = key_manager.generate_ec_key_pair(curve)
        
        if not is_authenticated():
            # For guests, return the key pair but don't save it
            return jsonify({
                "message": "EC key pair generated successfully (temporary)",
                "key_pair": key_pair,
                "note": "Log in to save keys permanently"
            })
        
        # Authenticated user flow - save the key
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Save the key to the database
        key_id = key_manager.save_key(
            name=name,
            key_type="EC",
            algorithm="ES256",
            key_data=key_pair["private_key"],
            user_id=user.id,
            is_public=is_public
        )
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="key_generated",
            username=current_user,
            details=f"EC key pair generated (curve: {curve})"
        )
        
        return jsonify({
            "message": "EC key pair generated successfully",
            "key_id": key_id,
            "public_key": key_pair["public_key"]
        })
    
    @app.route('/api/keys/generate-hmac', methods=['POST'])
    @jwt_optional
    @limiter.limit("10/minute")
    def generate_hmac_key():
        """Generate a new HMAC secret"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        
        key_size = data.get('key_size', 32)
        name = data.get('name', 'HMAC Secret')
        is_public = data.get('is_public', False)
        
        # Generate the key
        key_manager = g.key_manager
        secret = key_manager.generate_hmac_secret(key_size)
        
        if not is_authenticated():
            # For guests, return the secret but don't save it
            return jsonify({
                "message": "HMAC secret generated successfully (temporary)",
                "secret": secret,
                "note": "Log in to save keys permanently"
            })
        
        # Authenticated user flow - save the key
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Save the key to the database
        key_id = key_manager.save_key(
            name=name,
            key_type="HMAC",
            algorithm="HS256",
            key_data=secret,
            user_id=user.id,
            is_public=is_public
        )
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="key_generated",
            username=current_user,
            details=f"HMAC secret generated ({key_size} bytes)"
        )
        
        return jsonify({
            "message": "HMAC secret generated successfully",
            "key_id": key_id,
            "secret": secret
        })
    
    @app.route('/api/keys/jwks', methods=['GET'])
    def get_jwks():
        """
        Get public JWKS for verification purposes
        This endpoint is public to allow token verification
        """
        key_manager = g.key_manager
        jwks = key_manager.export_jwks(include_private=False)
        
        return jsonify(jwks) 