from flask import Blueprint, request, jsonify, g
from attack_simulator import JWTSecurityTester
from audit_manager import AuditLogManager
import jwt
import time
from datetime import datetime
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from jwt_optional import jwt_optional, get_current_user, is_authenticated
import json
from db import db, SavedToken, VulnerabilityReport, User, KeyStore

api = Blueprint('api', __name__)

# Initialize audit log manager
audit_manager = AuditLogManager(save_interval=300)  # Save every 5 minutes

# In-memory storage for token history (in production this should be a database)
token_history = []

def register_routes(app, limiter):
    """
    Register all routes for the JWT Kit API.
    
    Args:
        app: Flask application instance
        limiter: Flask-Limiter instance for rate limiting
    """
    
    # Import API modules
    from api.token_manipulation import register_token_routes
    from api.key_management import register_key_routes
    from api.vulnerability_scanning import register_vulnerability_routes
    from api.attack_simulation import register_attack_routes
    from api.audit import register_audit_routes
    from api.user_management import register_user_routes
    
    # Register all API route groups
    register_token_routes(app, limiter)
    register_key_routes(app, limiter)
    register_vulnerability_routes(app, limiter)
    register_attack_routes(app, limiter)
    register_audit_routes(app, limiter)
    register_user_routes(app, limiter)
    
    # Register general routes
    
    @app.route('/api/saved-tokens', methods=['GET'])
    @jwt_optional
    def get_saved_tokens():
        """Get all saved tokens for the current user or public tokens for guests"""
        if is_authenticated():
            # Authenticated user flow
            current_user = get_jwt_identity()
            user = User.query.filter_by(username=current_user).first()
            
            if not user:
                return jsonify({"error": "User not found"}), 404
                
            # Get tokens that are either public or owned by the user
            tokens = SavedToken.query.filter(
                (SavedToken.user_id == user.id) | (SavedToken.is_public == True)
            ).all()
        else:
            # Guest user flow - only return public tokens
            tokens = SavedToken.query.filter_by(is_public=True).all()
        
        return jsonify({
            "tokens": [token.to_dict() for token in tokens]
        })
    
    @app.route('/api/saved-tokens', methods=['POST'])
    @jwt_optional
    def save_token():
        """Save a token for future reference"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        
        if not is_authenticated():
            # Guest user flow
            return jsonify({
                "message": "Token saved in temporary storage. Log in to save tokens permanently.",
                "is_temporary": True,
                "token": data.get('token')
            })
        
        # Authenticated user flow
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Create a new SavedToken instance with the provided data
        token = SavedToken()
        token.name = data.get('name', 'Unnamed Token')
        token.token = data.get('token')
        token.user_id = user.id
        token.description = data.get('description')
        token.is_public = data.get('is_public', False)
        token.tags = ','.join(data.get('tags', []))
        
        db.session.add(token)
        db.session.commit()
        
        g.audit_manager.log_event(
            event_type="token_saved",
            username=current_user,
            details=f"Token saved: {data.get('name', 'Unnamed Token')}"
        )
        
        return jsonify({
            "message": "Token saved successfully",
            "token_id": token.id
        })
    
    @app.route('/api/saved-tokens/<int:token_id>', methods=['DELETE'])
    @jwt_required()
    def delete_token(token_id):
        """Delete a saved token"""
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        token = SavedToken.query.get(token_id)
        
        if not token:
            return jsonify({"error": "Token not found"}), 404
            
        # Only the owner can delete a token
        if token.user_id != user.id:
            return jsonify({"error": "Unauthorized"}), 403
            
        db.session.delete(token)
        db.session.commit()
        
        g.audit_manager.log_event(
            event_type="token_deleted",
            username=current_user,
            details=f"Token deleted: {token.name}"
        )
        
        return jsonify({
            "message": "Token deleted successfully"
        })
    
    @app.route('/api/vulnerability-reports', methods=['GET'])
    @jwt_optional
    def get_vulnerability_reports():
        """Get vulnerability reports for the current user or public reports for guests"""
        if is_authenticated():
            # Authenticated user flow
            current_user = get_jwt_identity()
            user = User.query.filter_by(username=current_user).first()
            
            if not user:
                return jsonify({"error": "User not found"}), 404
                
            reports = VulnerabilityReport.query.filter_by(user_id=user.id).all()
        else:
            # Guest user flow - return demo reports
            reports = []
        
        return jsonify({
            "reports": [report.to_dict() for report in reports]
        })
    
    @app.route('/api/vulnerability-reports', methods=['POST'])
    @jwt_optional
    def save_vulnerability_report():
        """Save a vulnerability report"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        
        if not is_authenticated():
            # Guest user flow
            return jsonify({
                "message": "Report saved in temporary storage. Log in to save reports permanently.",
                "is_temporary": True
            })
        
        # Authenticated user flow
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Create a new VulnerabilityReport instance with the provided data
        report = VulnerabilityReport()
        report.token_name = data.get('token_name')
        report.token = data.get('token')
        report.user_id = user.id
        report.results = json.dumps(data.get('results', {}))
        report.risk_score = data.get('risk_score')
        
        db.session.add(report)
        db.session.commit()
        
        g.audit_manager.log_event(
            event_type="vulnerability_report_saved",
            username=current_user,
            details=f"Vulnerability report saved: {data.get('token_name', 'Unnamed Token')}"
        )
        
        return jsonify({
            "message": "Vulnerability report saved successfully",
            "report_id": report.id
        })
        
    @app.route('/api/health', methods=['GET'])
    def api_health_check():
        """API health check endpoint"""
        return jsonify({
            "status": "healthy",
            "version": "2.0.0"
        })

