from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    role = db.Column(db.String(20), default='user')  # admin, user, auditor
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(64), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    success = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'username': self.username,
            'ip_address': self.ip_address,
            'details': self.details,
            'user_agent': self.user_agent,
            'success': self.success
        }

class SavedToken(db.Model):
    __tablename__ = 'saved_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    token = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_public = db.Column(db.Boolean, default=False)
    tags = db.Column(db.String(200), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'token': self.token,
            'user_id': self.user_id,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'is_public': self.is_public,
            'tags': self.tags.split(',') if self.tags else []
        }

class KeyStore(db.Model):
    __tablename__ = 'key_store'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    key_type = db.Column(db.String(20), nullable=False)  # RSA, EC, HMAC, etc.
    algorithm = db.Column(db.String(20), nullable=False)  # RS256, HS256, etc.
    key_data = db.Column(db.Text, nullable=False)  # Private key, public key, or secret
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_public = db.Column(db.Boolean, default=False)
    
    def to_dict(self, include_sensitive=False):
        data = {
            'id': self.id,
            'name': self.name,
            'key_type': self.key_type,
            'algorithm': self.algorithm,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'is_public': self.is_public
        }
        
        if include_sensitive:
            data['key_data'] = self.key_data
            
        return data

class VulnerabilityReport(db.Model):
    __tablename__ = 'vulnerability_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    token_name = db.Column(db.String(100), nullable=True)
    token = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.Column(db.Text, nullable=False)  # JSON string of vulnerability findings
    risk_score = db.Column(db.Integer, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'token_name': self.token_name,
            'token': self.token,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'results': self.results,
            'risk_score': self.risk_score
        } 