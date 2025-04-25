#!/usr/bin/env python3
from flask import Flask
from db import db, User
from werkzeug.security import generate_password_hash
import os

# Create a minimal Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///jwtkit.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True  # Enable SQL logging

# Initialize the database
db.init_app(app)

# Create a user
def create_user(username, password, email=None, role='user'):
    """Create a new user in the database."""
    with app.app_context():
        print(f"Creating database tables in {os.getcwd()}/jwtkit.db")
        # Create all tables if they don't exist
        db.create_all()
        
        # Print the tables that were created
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"Database tables: {tables}")
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User '{username}' already exists.")
            return False
            
        # Create new user with explicit column names to match the model
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            role=role
        )
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()
        
        # Query to verify user was created
        all_users = User.query.all()
        print(f"Users in database: {[u.username for u in all_users]}")
        
        print(f"User '{username}' created successfully with role '{role}'.")
        return True

if __name__ == "__main__":
    # Create the user with username "eshanized" and password "eshanized"
    create_user("eshanized", "eshanized") 