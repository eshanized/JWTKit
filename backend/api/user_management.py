from flask import request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt, create_access_token
from db import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid

def register_user_routes(app, limiter):
    """
    Register routes for user management.
    
    Routes include:
    - User registration
    - User profile management
    - Password change
    - User listing (admin)
    - User role management (admin)
    """
    
    @app.route('/api/auth/register', methods=['POST'])
    @limiter.limit("10/hour")
    def register_user():
        """Register a new user"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
            
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 409
            
        # Check if email already exists (if provided)
        if email and User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 409
            
        # Create new user
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            role='user',  # Default role
            created_at=datetime.utcnow()
        )
        
        # Save to database
        db.session.add(user)
        db.session.commit()
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="user_registered",
            username=username,
            details=f"New user registered: {username}",
            ip_address=request.remote_addr
        )
        
        # Generate access token
        access_token = create_access_token(
            identity=username,
            additional_claims={"role": "user"}
        )
        
        return jsonify({
            "message": "User registered successfully",
            "access_token": access_token,
            "user": {
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        }), 201
    
    @app.route('/api/auth/login', methods=['POST'])
    @limiter.limit("20/minute")
    def login():
        """Authenticate a user and return a JWT token"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
            
        # Check if user exists
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            # Log failed login attempt
            g.audit_manager.log_event(
                event_type="authentication",
                username=username,
                details="Failed login attempt",
                ip_address=request.remote_addr,
                success=False
            )
            return jsonify({"error": "Invalid credentials"}), 401
            
        # Update last login timestamp
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Generate access token
        access_token = create_access_token(
            identity=username,
            additional_claims={"role": user.role}
        )
        
        # Log successful login
        g.audit_manager.log_event(
            event_type="authentication",
            username=username,
            details="User login successful",
            ip_address=request.remote_addr,
            success=True
        )
        
        return jsonify({
            "access_token": access_token,
            "user": {
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        })
    
    @app.route('/api/auth/user', methods=['GET'])
    @jwt_required()
    def get_user_profile():
        """Get current user's profile"""
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify({
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None
        })
    
    @app.route('/api/auth/profile', methods=['PUT'])
    @jwt_required()
    def update_profile():
        """Update user profile information"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Update email if provided
        if 'email' in data:
            # Check if email already exists
            if data['email'] != user.email and User.query.filter_by(email=data['email']).first():
                return jsonify({"error": "Email already registered to another user"}), 409
                
            user.email = data['email']
            
        # Save changes
        db.session.commit()
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="profile_updated",
            username=current_user,
            details="User profile updated",
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "message": "Profile updated successfully",
            "user": {
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        })
    
    @app.route('/api/auth/change-password', methods=['POST'])
    @jwt_required()
    @limiter.limit("5/hour")
    def change_password():
        """Change user password"""
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({"error": "Current and new passwords are required"}), 400
            
        # Verify current password
        if not check_password_hash(user.password_hash, current_password):
            # Log failed password change attempt
            g.audit_manager.log_event(
                event_type="password_change_attempt",
                username=current_user,
                details="Failed password change attempt - incorrect current password",
                ip_address=request.remote_addr,
                success=False
            )
            return jsonify({"error": "Current password is incorrect"}), 401
            
        # Update password
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="password_changed",
            username=current_user,
            details="User password changed successfully",
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "message": "Password changed successfully"
        })
    
    @app.route('/api/users', methods=['GET'])
    @jwt_required()
    def list_users():
        """Get list of users (admin only)"""
        # Check admin permissions
        claims = get_jwt()
        role = claims.get('role', 'user')
        
        if role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
            
        # Get query parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        
        # Build query
        query = User.query
        
        # Get total count for pagination
        total_count = query.count()
        
        # Apply pagination
        users = query.offset((page - 1) * limit).limit(limit).all()
        
        # Log the activity
        current_user = get_jwt_identity()
        g.audit_manager.log_event(
            event_type="users_listed",
            username=current_user,
            details=f"Admin listed {len(users)} users",
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "users": [user.to_dict() for user in users],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_count,
                "pages": (total_count + limit - 1) // limit
            }
        })
    
    @app.route('/api/users/<int:user_id>', methods=['GET'])
    @jwt_required()
    def get_user(user_id):
        """Get user by ID (admin only)"""
        # Check admin permissions
        claims = get_jwt()
        role = claims.get('role', 'user')
        current_user = get_jwt_identity()
        
        # Allow users to view their own profile
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        if role != 'admin' and user.username != current_user:
            return jsonify({"error": "Permission denied"}), 403
            
        # Log the activity
        g.audit_manager.log_event(
            event_type="user_viewed",
            username=current_user,
            details=f"User viewed: {user.username}",
            ip_address=request.remote_addr
        )
        
        return jsonify(user.to_dict())
    
    @app.route('/api/users/<int:user_id>/role', methods=['PUT'])
    @jwt_required()
    def change_user_role(user_id):
        """Change user role (admin only)"""
        # Check admin permissions
        claims = get_jwt()
        role = claims.get('role', 'user')
        
        if role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
            
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
            
        data = request.json or {}
        new_role = data.get('role')
        
        if not new_role:
            return jsonify({"error": "New role is required"}), 400
            
        if new_role not in ['user', 'admin', 'auditor']:
            return jsonify({"error": "Invalid role. Must be one of: user, admin, auditor"}), 400
            
        # Get user by ID
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Don't allow changing your own role
        current_user = get_jwt_identity()
        if user.username == current_user:
            return jsonify({"error": "Cannot change your own role"}), 403
            
        # Update role
        user.role = new_role
        db.session.commit()
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="user_role_changed",
            username=current_user,
            details=f"Changed role for user {user.username} to {new_role}",
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "message": "User role updated successfully",
            "user": user.to_dict()
        })
    
    @app.route('/api/users/<int:user_id>', methods=['DELETE'])
    @jwt_required()
    def delete_user(user_id):
        """Delete user (admin only)"""
        # Check admin permissions
        claims = get_jwt()
        role = claims.get('role', 'user')
        
        if role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
            
        # Get user by ID
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Don't allow deleting yourself
        current_user = get_jwt_identity()
        if user.username == current_user:
            return jsonify({"error": "Cannot delete your own account"}), 403
            
        # Delete user
        username = user.username  # Save for logging
        db.session.delete(user)
        db.session.commit()
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="user_deleted",
            username=current_user,
            details=f"Deleted user: {username}",
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "message": "User deleted successfully"
        }) 