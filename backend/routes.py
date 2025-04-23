from flask import Blueprint, request, jsonify
from attack_simulator import (
    none_algorithm_attack, algorithm_confusion_attack, jwt_brute_force,
    kid_injection_attack, jwks_spoofing, token_expiration_bypass,
    test_token_against_endpoint
)

api = Blueprint('api', __name__)

@api.route('/attacks/none_algorithm', methods=['POST'])
def none_algorithm():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        result = none_algorithm_attack(data['token'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/algorithm_confusion', methods=['POST'])
def algorithm_confusion():
    data = request.get_json()
    if not data or 'token' not in data or 'public_key' not in data:
        return jsonify({"error": "Token and public key are required"}), 400
    
    try:
        result = algorithm_confusion_attack(data['token'], data['public_key'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/brute_force', methods=['POST'])
def brute_force():
    data = request.get_json()
    if not data or 'token' not in data or 'wordlist' not in data:
        return jsonify({"error": "Token and wordlist are required"}), 400
    
    try:
        result = jwt_brute_force(data['token'], data['wordlist'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/kid_injection', methods=['POST'])
def kid_injection():
    data = request.get_json()
    if not data or 'token' not in data or 'kid_value' not in data:
        return jsonify({"error": "Token and kid_value are required"}), 400
    
    try:
        result = kid_injection_attack(data['token'], data['kid_value'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/jwks_spoof', methods=['POST'])
def jwks_spoof():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        result = jwks_spoofing(data['token'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/expiration_bypass', methods=['POST'])
def expiration_bypass():
    data = request.get_json()
    if not data or 'token' not in data:
        return jsonify({"error": "Token is required"}), 400
    
    try:
        result = token_expiration_bypass(data['token'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/attacks/test_endpoint', methods=['POST'])
def test_endpoint():
    data = request.get_json()
    if not data or 'token' not in data or 'url' not in data or 'method' not in data:
        return jsonify({"error": "Token, URL, and method are required"}), 400
    
    try:
        result = test_token_against_endpoint(data['token'], data['url'], data['method'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500 