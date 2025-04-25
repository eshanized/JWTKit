from flask import request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from db import db, AuditLog, User
from datetime import datetime, timedelta

def register_audit_routes(app, limiter):
    """
    Register routes for audit logging and reporting.
    
    Routes include:
    - Get audit logs
    - Get audit metrics
    - Export audit logs
    - Get security alerts
    """
    
    @app.route('/api/audit', methods=['GET'])
    @jwt_required()
    @limiter.limit("30/minute")
    def get_audit_logs():
        """Get audit logs with optional filtering"""
        # Get query parameters for filtering
        event_type = request.args.get('event_type')
        username = request.args.get('username')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        ip_address = request.args.get('ip_address')
        limit = int(request.args.get('limit', 100))
        page = int(request.args.get('page', 1))
        
        # Get current user and check permissions
        current_user = get_jwt_identity()
        claims = get_jwt()
        role = claims.get('role', 'user')
        
        # Build the query
        query = AuditLog.query
        
        # Apply filters
        if event_type:
            query = query.filter(AuditLog.event_type == event_type)
            
        if ip_address:
            query = query.filter(AuditLog.ip_address == ip_address)
            
        # Date filtering
        if start_date:
            try:
                start = datetime.fromisoformat(start_date)
                query = query.filter(AuditLog.timestamp >= start)
            except ValueError:
                return jsonify({"error": "Invalid start_date format, use ISO format (YYYY-MM-DDThh:mm:ss)"}), 400
                
        if end_date:
            try:
                end = datetime.fromisoformat(end_date)
                query = query.filter(AuditLog.timestamp <= end)
            except ValueError:
                return jsonify({"error": "Invalid end_date format, use ISO format (YYYY-MM-DDThh:mm:ss)"}), 400
        
        # Regular users can only see their own logs, admins can see all or filter by username
        if role != 'admin':
            query = query.filter(AuditLog.username == current_user)
        elif username:
            query = query.filter(AuditLog.username == username)
            
        # Get total count for pagination
        total_count = query.count()
        
        # Apply pagination
        query = query.order_by(AuditLog.timestamp.desc())
        query = query.offset((page - 1) * limit).limit(limit)
        
        # Execute query
        logs = query.all()
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="audit_logs_viewed",
            username=current_user,
            details=f"Viewed {len(logs)} audit logs"
        )
        
        return jsonify({
            "logs": [log.to_dict() for log in logs],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_count,
                "pages": (total_count + limit - 1) // limit
            }
        })
    
    @app.route('/api/audit/metrics', methods=['GET'])
    @jwt_required()
    @limiter.limit("10/minute")
    def get_audit_metrics():
        """Get metrics and statistics from audit logs"""
        # Check admin permissions
        claims = get_jwt()
        role = claims.get('role', 'user')
        
        if role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
            
        # Get time period for metrics
        days = int(request.args.get('days', 30))
        
        # Get metrics from audit manager
        audit_manager = g.audit_manager
        metrics = audit_manager.get_security_metrics(days=days)
        
        # Log the activity
        current_user = get_jwt_identity()
        g.audit_manager.log_event(
            event_type="audit_metrics_accessed",
            username=current_user,
            details=f"Accessed audit metrics for past {days} days"
        )
        
        return jsonify(metrics)
    
    @app.route('/api/audit/export', methods=['GET'])
    @jwt_required()
    @limiter.limit("5/day")
    def export_audit_logs():
        """Export audit logs to a CSV format"""
        # Check admin permissions
        claims = get_jwt()
        role = claims.get('role', 'user')
        
        if role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
            
        # Get query parameters for filtering
        event_type = request.args.get('event_type')
        username = request.args.get('username')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build the query
        query = AuditLog.query
        
        # Apply filters
        if event_type:
            query = query.filter(AuditLog.event_type == event_type)
            
        if username:
            query = query.filter(AuditLog.username == username)
            
        # Date filtering
        if start_date:
            try:
                start = datetime.fromisoformat(start_date)
                query = query.filter(AuditLog.timestamp >= start)
            except ValueError:
                return jsonify({"error": "Invalid start_date format, use ISO format (YYYY-MM-DDThh:mm:ss)"}), 400
                
        if end_date:
            try:
                end = datetime.fromisoformat(end_date)
                query = query.filter(AuditLog.timestamp <= end)
            except ValueError:
                return jsonify({"error": "Invalid end_date format, use ISO format (YYYY-MM-DDThh:mm:ss)"}), 400
        
        # Order by timestamp
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Execute query
        logs = query.all()
        
        # Convert to CSV format (simplified for this example)
        csv_data = "id,timestamp,event_type,username,ip_address,details,user_agent,success\n"
        for log in logs:
            csv_data += f"{log.id},{log.timestamp},{log.event_type},{log.username},{log.ip_address},\"{log.details}\",\"{log.user_agent}\",{log.success}\n"
        
        # Log the activity
        current_user = get_jwt_identity()
        g.audit_manager.log_event(
            event_type="audit_logs_exported",
            username=current_user,
            details=f"Exported {len(logs)} audit logs"
        )
        
        # In a real implementation, would set proper headers for CSV download
        return jsonify({
            "csv_data": csv_data,
            "count": len(logs),
            "filters": {
                "event_type": event_type,
                "username": username,
                "start_date": start_date,
                "end_date": end_date
            }
        })
    
    @app.route('/api/audit/alerts', methods=['GET'])
    @jwt_required()
    @limiter.limit("30/minute")
    def get_security_alerts():
        """Get security alerts based on audit logs"""
        # Check permissions
        claims = get_jwt()
        role = claims.get('role', 'user')
        current_user = get_jwt_identity()
        
        # Regular users can only see their own alerts
        username_filter = None
        if role != 'admin':
            username_filter = current_user
        else:
            username_filter = request.args.get('username')
        
        # Get time period for alerts
        days = int(request.args.get('days', 7))
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Define security alert patterns
        alerts = []
        
        # 1. Failed authentication attempts
        query = AuditLog.query.filter(
            AuditLog.timestamp >= start_date,
            AuditLog.event_type == 'authentication',
            AuditLog.success == False
        )
        
        if username_filter:
            query = query.filter(AuditLog.username == username_filter)
            
        failed_auths = query.all()
        
        # Group by username to detect brute force
        username_counts = {}
        for log in failed_auths:
            if log.username not in username_counts:
                username_counts[log.username] = []
            username_counts[log.username].append(log)
        
        for username, logs in username_counts.items():
            if len(logs) >= 5:  # Threshold for alert
                alerts.append({
                    "level": "high",
                    "type": "brute_force_attempt",
                    "description": f"Multiple failed login attempts detected for user: {username}",
                    "timestamp": logs[-1].timestamp.isoformat(),
                    "count": len(logs),
                    "details": {
                        "username": username,
                        "ip_addresses": list(set(log.ip_address for log in logs if log.ip_address))
                    }
                })
        
        # 2. Attack simulation alerts
        query = AuditLog.query.filter(
            AuditLog.timestamp >= start_date,
            AuditLog.event_type.like('attack_%')
        )
        
        if username_filter:
            query = query.filter(AuditLog.username == username_filter)
            
        attack_logs = query.all()
        
        # Group by event type
        event_type_counts = {}
        for log in attack_logs:
            if log.event_type not in event_type_counts:
                event_type_counts[log.event_type] = []
            event_type_counts[log.event_type].append(log)
        
        for event_type, logs in event_type_counts.items():
            attack_name = event_type.replace('attack_', '').replace('_', ' ').title()
            alerts.append({
                "level": "medium",
                "type": "attack_activity",
                "description": f"{attack_name} attack activity detected",
                "timestamp": logs[-1].timestamp.isoformat(),
                "count": len(logs),
                "details": {
                    "attack_type": event_type,
                    "usernames": list(set(log.username for log in logs if log.username)),
                    "recent_activity": [log.to_dict() for log in logs[:3]]  # Include recent 3 logs
                }
            })
        
        # 3. Suspicious activity detection (admin operations)
        if role == 'admin':
            query = AuditLog.query.filter(
                AuditLog.timestamp >= start_date,
                AuditLog.event_type.in_(['key_deleted', 'user_deleted', 'user_role_changed'])
            )
            
            if username_filter:
                query = query.filter(AuditLog.username == username_filter)
                
            admin_logs = query.all()
            
            if admin_logs:
                alerts.append({
                    "level": "info",
                    "type": "admin_activity",
                    "description": "Administrative operations detected",
                    "timestamp": admin_logs[-1].timestamp.isoformat(),
                    "count": len(admin_logs),
                    "details": {
                        "operations": [log.to_dict() for log in admin_logs[:5]]  # Include recent 5 logs
                    }
                })
        
        # Log the activity
        g.audit_manager.log_event(
            event_type="security_alerts_viewed",
            username=current_user,
            details=f"Viewed {len(alerts)} security alerts"
        )
        
        return jsonify({
            "alerts": alerts,
            "total": len(alerts),
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            }
        }) 