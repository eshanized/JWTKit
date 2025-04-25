import json
import os
from datetime import datetime, timedelta
import threading
import time
import logging
from flask import current_app, request
from db import db, AuditLog

logger = logging.getLogger(__name__)

class AuditManager:
    """
    Manages audit logging and reporting for security events in the application.
    """
    
    def __init__(self):
        self.logger = logger
    
    def log_event(self, event_type, username=None, details=None, ip_address=None, user_agent=None, success=True):
        """
        Log a security event to the database and application logs.
        
        Args:
            event_type: Type of event (auth, token_generation, attack, etc.)
            username: Username associated with the event
            details: Detailed information about the event
            ip_address: IP address of the request
            user_agent: User agent of the request
            success: Whether the event was successful
        """
        try:
            # Get request information if not provided
            if not ip_address and request:
                ip_address = request.remote_addr
                
            if not user_agent and request:
                user_agent = request.headers.get('User-Agent')
            
            # Create audit log entry
            log_entry = AuditLog(
                event_type=event_type,
                username=username,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success
            )
            
            # Add to database
            db.session.add(log_entry)
            db.session.commit()
            
            # Also log to application logs
            log_message = f"AUDIT: {event_type} | User: {username or 'anonymous'} | IP: {ip_address} | Success: {success}"
            if success:
                self.logger.info(log_message)
            else:
                self.logger.warning(log_message)
                
            return log_entry.id
            
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {str(e)}")
            # Try to commit what we have so far
            db.session.rollback()
            return None
    
    def get_recent_events(self, limit=100, event_type=None, username=None):
        """
        Get recent audit events, optionally filtered by type or username.
        
        Args:
            limit: Maximum number of events to retrieve
            event_type: Filter by event type
            username: Filter by username
            
        Returns:
            List of audit events as dictionaries
        """
        query = AuditLog.query
        
        if event_type:
            query = query.filter(AuditLog.event_type == event_type)
            
        if username:
            query = query.filter(AuditLog.username == username)
            
        events = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
        return [event.to_dict() for event in events]
    
    def get_security_metrics(self, days=30):
        """
        Get security metrics for dashboard display.
        
        Args:
            days: Number of days to include in the metrics
            
        Returns:
            Dictionary of security metrics
        """
        from sqlalchemy import func
        from datetime import timedelta
        
        # Calculate the date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get event counts by type
        event_counts = db.session.query(
            AuditLog.event_type, 
            func.count(AuditLog.id)
        ).filter(
            AuditLog.timestamp >= start_date
        ).group_by(
            AuditLog.event_type
        ).all()
        
        # Get failed authentication attempts
        failed_auth = db.session.query(
            func.count(AuditLog.id)
        ).filter(
            AuditLog.timestamp >= start_date,
            AuditLog.event_type == 'authentication',
            AuditLog.success == False
        ).scalar() or 0
        
        # Get attack attempts
        attack_attempts = db.session.query(
            func.count(AuditLog.id)
        ).filter(
            AuditLog.timestamp >= start_date,
            AuditLog.event_type.like('attack_%')
        ).scalar() or 0
        
        # Format the metrics
        metrics = {
            'period': f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
            'total_events': sum(count for _, count in event_counts),
            'event_breakdown': {event_type: count for event_type, count in event_counts},
            'failed_authentication_attempts': failed_auth,
            'attack_attempts': attack_attempts
        }
        
        return metrics

class AuditLogManager:
    """Manages audit logs with periodic saving to disk"""
    
    def __init__(self, save_interval=300):  # 5 minutes default
        self.logs = []
        self.save_interval = save_interval
        self.lock = threading.Lock()
        self.log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        
        # Create logs directory if it doesn't exist
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        # Start background saving thread
        self.running = True
        self.save_thread = threading.Thread(target=self._periodic_save)
        self.save_thread.daemon = True
        self.save_thread.start()
    
    def add_log(self, log_entry):
        """Add a new log entry"""
        with self.lock:
            self.logs.append(log_entry)
    
    def get_logs(self, limit=None, filter_params=None):
        """Get logs with optional filtering"""
        with self.lock:
            filtered_logs = self.logs
            
            if filter_params:
                if 'severity' in filter_params:
                    filtered_logs = [log for log in filtered_logs 
                                   if log.get('severity') == filter_params['severity']]
                if 'action' in filter_params:
                    filtered_logs = [log for log in filtered_logs 
                                   if log.get('action') == filter_params['action']]
                if 'start_date' in filter_params:
                    start = datetime.fromisoformat(filter_params['start_date'])
                    filtered_logs = [log for log in filtered_logs 
                                   if datetime.fromisoformat(log.get('timestamp')) >= start]
                if 'end_date' in filter_params:
                    end = datetime.fromisoformat(filter_params['end_date'])
                    filtered_logs = [log for log in filtered_logs 
                                   if datetime.fromisoformat(log.get('timestamp')) <= end]
            
            if limit:
                return filtered_logs[-limit:]
            return filtered_logs
    
    def _get_log_filename(self):
        """Generate a filename for the current log file"""
        current_date = datetime.now().strftime('%Y-%m-%d')
        return os.path.join(self.log_dir, f'audit_log_{current_date}.json')
    
    def _save_logs(self):
        """Save current logs to disk"""
        if not self.logs:
            return
            
        with self.lock:
            try:
                filename = self._get_log_filename()
                
                # Load existing logs if file exists
                existing_logs = []
                if os.path.exists(filename):
                    with open(filename, 'r') as f:
                        existing_logs = json.load(f)
                
                # Combine existing and new logs
                all_logs = existing_logs + self.logs
                
                # Save all logs
                with open(filename, 'w') as f:
                    json.dump(all_logs, f, indent=2)
                    
                # Clear in-memory logs after successful save
                self.logs = []
                
            except Exception as e:
                print(f"Error saving audit logs: {str(e)}")
    
    def _periodic_save(self):
        """Periodically save logs to disk"""
        while self.running:
            time.sleep(self.save_interval)
            self._save_logs()
    
    def stop(self):
        """Stop the periodic saving and save remaining logs"""
        self.running = False
        if self.save_thread.is_alive():
            self.save_thread.join()
        self._save_logs()
    
    def load_historical_logs(self, days=7):
        """Load historical logs from saved files"""
        historical_logs = []
        
        for i in range(days):
            date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
            filename = os.path.join(self.log_dir, f'audit_log_{date}.json')
            
            if os.path.exists(filename):
                try:
                    with open(filename, 'r') as f:
                        logs = json.load(f)
                        historical_logs.extend(logs)
                except Exception as e:
                    print(f"Error loading logs from {filename}: {str(e)}")
        
        return historical_logs