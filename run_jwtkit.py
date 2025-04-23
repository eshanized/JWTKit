#!/usr/bin/env python3
"""
JWTKit Integrated Server

This script combines all the JWT functionality from different modules
and launches a unified server.
"""

import os
import sys
import importlib
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('jwtkit')

# Add the current directory to sys.path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask and create app
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Function to safely import modules
def safe_import(module_name):
    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        logger.warning(f"Could not import {module_name}: {str(e)}")
        return None

# Import main routes
app_module = safe_import('app')
main_module = safe_import('backend.main')

# Import advanced functionality
advanced_api_module = safe_import('backend.advanced_api')

# Register routes
if app_module:
    logger.info("Importing routes from app.py")
    
    # Special handling for necessary routes for the AlgorithmConfusion component
    if hasattr(app_module, 'algorithm_confusion'):
        app.route('/algorithm-confusion', methods=['POST'])(app_module.algorithm_confusion)
        logger.info("Registered algorithm_confusion route")
    
    # Import other useful routes
    for route_name in ['brute_force', 'key_injection', 'jwks_spoofing', 'token_expiration_bypass']:
        if hasattr(app_module, route_name):
            route_function = getattr(app_module, route_name)
            route_path = f'/{route_name.replace("_", "-")}'
            app.route(route_path, methods=['POST'])(route_function)
            logger.info(f"Registered {route_path} route")

if advanced_api_module and hasattr(advanced_api_module, 'register_advanced_api'):
    logger.info("Registering advanced API")
    advanced_api_module.register_advanced_api(app)

# Default route
@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "status": "healthy",
        "service": "JWTKit API",
        "version": "1.0.0",
        "advanced_api": advanced_api_module is not None
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    debug = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    logger.info(f"Starting JWTKit API on port {port} (debug={debug})")
    app.run(host='0.0.0.0', port=port, debug=debug) 