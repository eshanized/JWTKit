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

# Mock exchange rates for simplicity
mock_exchange_rates = {
    "USD": 1.0,
    "EUR": 0.92,
    "GBP": 0.81,
    "JPY": 134.5,
    "AUD": 1.48,
    "CAD": 1.34,
    "CHF": 0.91,
    "CNY": 7.25,
    "NZD": 1.58
}

@api.route('/api/forex-rate', methods=['GET'])
def forex_rate():
    base_currency = request.args.get('base')
    target_currency = request.args.get('target')
    if not base_currency or not target_currency:
        return jsonify({"error": "Base and target currencies are required"}), 400
    
    base_currency = base_currency.upper()
    target_currency = target_currency.upper()
    
    if base_currency not in mock_exchange_rates or target_currency not in mock_exchange_rates:
        return jsonify({"error": "Unsupported currency"}), 400
    
    base_rate = mock_exchange_rates[base_currency]
    target_rate = mock_exchange_rates[target_currency]
    
    # Calculate price differential (target per base)
    price_differential = target_rate / base_rate
    
    return jsonify({
        "base_currency": base_currency,
        "target_currency": target_currency,
        "price_differential": price_differential
    })

