from flask import Blueprint, request, jsonify
from attack_simulator import JWTSecurityTester
from audit_manager import AuditLogManager
import jwt
import time
from datetime import datetime

api = Blueprint('api', __name__)

# Initialize audit log manager
audit_manager = AuditLogManager(save_interval=300)  # Save every 5 minutes

# In-memory storage for token history (in production this should be a database)
token_history = []

@api.route('/attacks/none_algorithm', methods=['POST'])
def none_algorithm():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        result = JWTSecurityTester.none_algorithm_attack(data['token'])
        log_attack_attempt(
            "None Algorithm Attack",
            "Attempted to bypass signature verification using 'none' algorithm",
            "high",
            result.get('success', False),
            data['token']
        )
        return jsonify(result)
    except Exception as e:
        log_attack_attempt(
            "None Algorithm Attack",
            f"Attack failed: {str(e)}",
            "high",
            False,
            data['token']
        )
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/algorithm_confusion', methods=['POST'])
def algorithm_confusion():
    data = request.get_json()
    if not data or 'token' not in data or 'public_key' not in data:
        return jsonify({"error": "Token and public key are required"}), 400
    
    try:
        result = JWTSecurityTester.algorithm_confusion_attack(data['token'], data['public_key'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/brute_force', methods=['POST'])
def brute_force():
    data = request.get_json()
    if not data or 'token' not in data or 'wordlist' not in data:
        return jsonify({"error": "Token and wordlist are required"}), 400
    
    try:
        result = JWTSecurityTester.jwt_brute_force(data['token'], data['wordlist'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/kid_injection', methods=['POST'])
def kid_injection():
    data = request.get_json()
    if not data or 'token' not in data or 'kid_value' not in data:
        return jsonify({"error": "Token and kid_value are required"}), 400
    
    try:
        result = JWTSecurityTester.kid_injection_attack(data['token'], data['kid_value'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/jwks_spoof', methods=['POST'])
def jwks_spoof():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        result = JWTSecurityTester.jwks_spoofing(data['token'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/expiration_bypass', methods=['POST'])
def expiration_bypass():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        result = JWTSecurityTester.token_expiration_bypass(data['token'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/test_endpoint', methods=['POST'])
def test_endpoint():
    data = request.get_json()
    if not data or 'token' not in data or 'url' not in data or 'method' not in data:
        return jsonify({"error": "Token, URL, and method are required"}), 400
    
    try:
        result = JWTSecurityTester.test_token_against_endpoint(data['token'], data['url'], data['method'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/jwk_injection', methods=['POST'])
def jwk_injection():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        result = JWTSecurityTester.jwk_injection_attack(data['token'])
        log_attack_attempt(
            "JWK Injection Attack",
            "Attempted to inject malicious JWK into token header",
            "high",
            result.get('success', False),
            data['token']
        )
        return jsonify(result)
    except Exception as e:
        log_attack_attempt(
            "JWK Injection Attack",
            f"Attack failed: {str(e)}",
            "high",
            False,
            data['token']
        )
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/x5c_injection', methods=['POST'])
def x5c_injection():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        result = JWTSecurityTester.x5c_injection_attack(data['token'])
        log_attack_attempt(
            "X.509 Certificate Injection Attack",
            "Attempted to inject malicious X.509 certificate into token header",
            "high",
            result.get('success', False),
            data['token']
        )
        return jsonify(result)
    except Exception as e:
        log_attack_attempt(
            "X.509 Certificate Injection Attack",
            f"Attack failed: {str(e)}",
            "high",
            False,
            data['token']
        )
        return jsonify({"error": str(e)}), 500

@api.route('/history', methods=['GET'])
def get_history():
    return jsonify(token_history)

@api.route('/history', methods=['POST'])
def add_to_history():
    data = request.json
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    entry = {
        "value": data['token'],
        "operation": data.get('operation', 'unknown'),
        "timestamp": data.get('timestamp', time.time() * 1000),
        "status": data.get('status', 'unknown'),
        "notes": data.get('notes', '')
    }
    
    token_history.append(entry)
    return jsonify(entry)

@api.route('/test', methods=['POST'])
def test_token():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        header = jwt.get_unverified_header(data['token'])
        payload = jwt.decode(data['token'], options={"verify_signature": False})
        
        # Basic validation tests
        validation_results = []
        
        # Check for none algorithm
        if header.get('alg') == 'none':
            validation_results.append({
                "type": "alg_none",
                "description": "Token uses 'none' algorithm",
                "severity": "high"
            })
            
        # Check for known dangerous claims
        if payload.get('admin', False):
            validation_results.append({
                "type": "admin_claim",
                "description": "Token contains admin claim set to true",
                "severity": "high"
            })
            
        # Check for SQL injection attempts in kid
        kid = header.get('kid', '')
        sql_patterns = ["'", "SELECT", "UNION", "--"]
        if any(pattern.lower() in kid.lower() for pattern in sql_patterns):
            validation_results.append({
                "type": "kid_sql",
                "description": "Potential SQL injection in kid header",
                "severity": "high"
            })
            
        # Check for path traversal in kid
        if '../' in kid or '..\\' in kid:
            validation_results.append({
                "type": "kid_path_traversal",
                "description": "Potential path traversal in kid header",
                "severity": "high"
            })
            
        # Check for expired token
        if 'exp' in payload:
            try:
                jwt.decode(data['token'], options={"verify_signature": False, "verify_exp": True})
            except jwt.ExpiredSignatureError:
                validation_results.append({
                    "type": "expired",
                    "description": "Token is expired",
                    "severity": "medium"
                })
            
        return jsonify({
            "success": True,
            "header": header,
            "payload": payload,
            "validation_results": validation_results
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@api.route('/audit-log', methods=['GET'])
def get_audit_log():
    # Get filter parameters from query string
    filter_params = {}
    if request.args.get('severity'):
        filter_params['severity'] = request.args.get('severity')
    if request.args.get('action'):
        filter_params['action'] = request.args.get('action')
    if request.args.get('start_date'):
        filter_params['start_date'] = request.args.get('start_date')
    if request.args.get('end_date'):
        filter_params['end_date'] = request.args.get('end_date')
    
    # Get limit parameter
    limit = request.args.get('limit', type=int)
    
    # Load historical logs if requested
    include_historical = request.args.get('historical', 'false').lower() == 'true'
    
    if include_historical:
        historical_logs = audit_manager.load_historical_logs()
        current_logs = audit_manager.get_logs(limit, filter_params)
        return jsonify(historical_logs + current_logs)
    
    return jsonify(audit_manager.get_logs(limit, filter_params))

@api.route('/audit-log', methods=['POST'])
def add_audit_log():
    data = request.json
    if not data or 'action' not in data:
        return jsonify({"error": "Action is required"}), 400
    
    log_entry = {
        "timestamp": data.get('timestamp', datetime.now().isoformat()),
        "action": data['action'],
        "details": data.get('details', ''),
        "severity": data.get('severity', 'info'),
        "success": data.get('success', True),
        "token": data.get('token', ''),
        "ip_address": request.remote_addr
    }
    
    audit_manager.add_log(log_entry)
    return jsonify(log_entry)

def log_attack_attempt(action, details, severity, success=True, token=None):
    """Helper function to log attack attempts"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details,
        "severity": severity,
        "success": success,
        "token": token,
        "ip_address": request.remote_addr
    }
    audit_manager.add_log(log_entry)
    return log_entry