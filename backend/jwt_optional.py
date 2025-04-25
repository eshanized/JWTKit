from functools import wraps
from flask import g, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

def jwt_optional(fn):
    """
    A decorator to make JWT authentication optional.
    
    If a valid JWT token is provided, it will authenticate the user.
    If no token is provided or it's invalid, it will continue with a guest user.
    
    This enables features to work for both authenticated and non-authenticated users.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            # Try to verify JWT token if present
            verify_jwt_in_request(optional=True)
            
            # If we get here and have a JWT identity, user is authenticated
            identity = get_jwt_identity()
            
            if identity:
                # User is authenticated
                g.is_authenticated = True
                g.current_user = identity
            else:
                # No valid JWT token - using as guest
                g.is_authenticated = False
                g.current_user = 'guest'
        except Exception:
            # Error processing JWT - using as guest
            g.is_authenticated = False
            g.current_user = 'guest'
        
        return fn(*args, **kwargs)
    
    return wrapper

def get_current_user():
    """Helper function to get the current user (authenticated or guest)"""
    if hasattr(g, 'current_user'):
        return g.current_user
    return 'guest'

def is_authenticated():
    """Helper function to check if the current request is authenticated"""
    return hasattr(g, 'is_authenticated') and g.is_authenticated 