from flask import request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity
from db import db, User
import json
import base64

def register_token_routes(app, limiter):
    """
    Register routes for JWT token manipulation.
    
    Routes include:
    - Decode token
    - Encode token
    - Modify token payload
    - Modify token header
    - Check token signature
    """
    
    @app.route('/api/tokens/decode', methods=['POST'])
    @limiter.limit("30/minute")
    def decode_token():
        """Decode a JWT token without verifying the signature"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        token = data.get('token', '')
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
        
        # Use JWT utils to decode the token
        jwt_utils = g.jwt_utils
        decoded = jwt_utils.decode_token_parts(token)
        
        # Log the activity
        username = get_jwt_identity() if hasattr(g, 'jwt') else "anonymous"
        g.audit_manager.log_event(
            event_type="token_decoded",
            username=username,
            details="Token decoded"
        )
        
        return jsonify(decoded)
    
    @app.route('/api/tokens/encode', methods=['POST'])
    @limiter.limit("20/minute")
    def encode_token():
        """Encode a new JWT token with provided header and payload"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        header = data.get('header', {})
        payload = data.get('payload', {})
        key = data.get('key', '')
        algorithm = data.get('algorithm', 'HS256')
        
        if not payload:
            return jsonify({"error": "Payload is required"}), 400
            
        # Set default values for header if not provided
        if not header.get('alg'):
            header['alg'] = algorithm
        if not header.get('typ'):
            header['typ'] = 'JWT'
        
        # Use JWT utils to encode the token
        jwt_utils = g.jwt_utils
        token = jwt_utils.create_token(payload, key, algorithm, header)
        
        # Log the activity
        username = get_jwt_identity() if hasattr(g, 'jwt') else "anonymous"
        g.audit_manager.log_event(
            event_type="token_created",
            username=username,
            details=f"Token created with algorithm: {algorithm}"
        )
        
        return jsonify({
            "token": token,
            "header": header,
            "payload": payload
        })
    
    @app.route('/api/tokens/modify-payload', methods=['POST'])
    @limiter.limit("20/minute")
    def modify_token_payload():
        """Modify the payload of an existing JWT token"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        token = data.get('token', '')
        modifications = data.get('modifications', {})
        key = data.get('key', '')
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
            
        if not modifications:
            return jsonify({"error": "Modifications are required"}), 400
            
        # Use JWT utils to decode and modify the token
        jwt_utils = g.jwt_utils
        decoded = jwt_utils.decode_token_parts(token)
        
        if "error" in decoded:
            return jsonify({"error": decoded["error"]}), 400
            
        # Apply modifications to the payload
        payload = decoded["payload"]
        for k, v in modifications.items():
            if v is None:
                if k in payload:
                    del payload[k]
            else:
                payload[k] = v
        
        # Create a new token with the modified payload
        header = decoded["header"]
        algorithm = header.get('alg', 'HS256')
        modified_token = jwt_utils.create_token(payload, key, algorithm, header)
        
        # Log the activity
        username = get_jwt_identity() if hasattr(g, 'jwt') else "anonymous"
        g.audit_manager.log_event(
            event_type="token_modified",
            username=username,
            details=f"Token payload modified: {list(modifications.keys())}"
        )
        
        return jsonify({
            "original_token": token,
            "modified_token": modified_token,
            "header": header,
            "payload": payload
        })
    
    @app.route('/api/tokens/modify-header', methods=['POST'])
    @limiter.limit("20/minute")
    def modify_token_header():
        """Modify the header of an existing JWT token"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        token = data.get('token', '')
        modifications = data.get('modifications', {})
        key = data.get('key', '')
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
            
        if not modifications:
            return jsonify({"error": "Modifications are required"}), 400
            
        # Use JWT utils to decode and modify the token
        jwt_utils = g.jwt_utils
        decoded = jwt_utils.decode_token_parts(token)
        
        if "error" in decoded:
            return jsonify({"error": decoded["error"]}), 400
            
        # Apply modifications to the header
        header = decoded["header"]
        for k, v in modifications.items():
            if v is None:
                if k in header:
                    del header[k]
            else:
                header[k] = v
        
        # Create a new token with the modified header
        payload = decoded["payload"]
        algorithm = header.get('alg', 'HS256')
        modified_token = jwt_utils.create_token(payload, key, algorithm, header)
        
        # Log the activity
        username = get_jwt_identity() if hasattr(g, 'jwt') else "anonymous"
        g.audit_manager.log_event(
            event_type="token_modified",
            username=username,
            details=f"Token header modified: {list(modifications.keys())}"
        )
        
        return jsonify({
            "original_token": token,
            "modified_token": modified_token,
            "header": header,
            "payload": payload
        })
    
    @app.route('/api/tokens/verify', methods=['POST'])
    @limiter.limit("30/minute")
    def verify_token():
        """Verify a JWT token signature"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        token = data.get('token', '')
        key = data.get('key', '')
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
            
        # Use JWT utils to verify the token
        jwt_utils = g.jwt_utils
        result = jwt_utils.verify_token(token, key)
        
        # Log the activity
        username = get_jwt_identity() if hasattr(g, 'jwt') else "anonymous"
        g.audit_manager.log_event(
            event_type="token_verified",
            username=username,
            details=f"Token verification: {'success' if result.get('valid') else 'failure'}"
        )
        
        return jsonify(result) 