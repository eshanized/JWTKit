import json
import os
from datetime import datetime, timedelta
import threading
import time

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