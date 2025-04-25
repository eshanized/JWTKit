#!/usr/bin/env python3
from main import create_app
from db import db, User
from werkzeug.security import generate_password_hash
from datetime import datetime

def create_user(username, password, email=None, role='user'):
    """Create a new user in the database."""
    # Check if user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print(f"User '{username}' already exists.")
        return False
        
    # Create new user
    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        email=email,
        role=role
    )
    
    # Save to database
    db.session.add(new_user)
    db.session.commit()
    
    print(f"User '{username}' created successfully with role '{role}'.")
    return True

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        # Create the user with username "eshanized" and password "eshanized"
        create_user("eshanized", "eshanized") 