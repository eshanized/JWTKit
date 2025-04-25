from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
import logging
from datetime import timedelta
import importlib

# Load modules
from routes import register_routes
from jwt_utils import initialize_jwt_utils
from key_manager import KeyManager
from audit_manager import AuditManager
from db import db, User

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("jwtkit.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_app(config=None):
    app = Flask(__name__)
    
    # App configuration
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24).hex())
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", os.urandom(24).hex())
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///jwtkit.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    if config:
        app.config.update(config)
    
    # Initialize extensions
    CORS(app)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"]
    )
    jwt = JWTManager(app)
    db.init_app(app)
    
    # Initialize services
    key_manager = KeyManager()
    audit_manager = AuditManager()
    jwt_utils = initialize_jwt_utils()
    
    # Register the context processor to make services available to routes
    @app.context_processor
    def inject_services():
        return {
            "key_manager": key_manager,
            "audit_manager": audit_manager,
            "jwt_utils": jwt_utils
        }
    
    # Register all routes
    register_routes(app, limiter)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
            admin = User(
                username="admin",
                password_hash=generate_password_hash(admin_password),
                role="admin"
            )
            db.session.add(admin)
            db.session.commit()
            logger.info("Admin user created")
    
    # Health check endpoint
    @app.route('/', methods=['GET'])
    def health_check():
        return jsonify({
            "status": "healthy",
            "service": "JWTKit API",
            "version": "2.0.0"
        })
    
    # The login route is now registered in user_management.py, so we're commenting this out
    # to avoid the "View function mapping is overwriting an existing endpoint function" error
    
    '''
    # User authentication endpoints
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid credentials"}), 401
        
        access_token = create_access_token(
            identity=username,
            additional_claims={"role": user.role}
        )
        
        audit_manager.log_event(
            event_type="authentication",
            username=username,
            details="User login",
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "access_token": access_token,
            "user": {
                "username": user.username,
                "role": user.role
            }
        })
    '''
    
    # Dynamic module loading for extensibility
    @app.route('/api/modules/load', methods=['POST'])
    @jwt_required()
    def load_module():
        data = request.json
        module_name = data.get('module_name')
        
        if not module_name:
            return jsonify({"error": "Module name is required"}), 400
        
        try:
            # Safely import the module (should be in the modules directory)
            module = importlib.import_module(f"modules.{module_name}")
            return jsonify({"message": f"Module {module_name} loaded successfully"})
        except ImportError as e:
            return jsonify({"error": f"Failed to load module: {str(e)}"}), 400
    
    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    
    logger.info(f"Starting JWTKit API on port {port}, debug mode: {debug}")
    app.run(host="0.0.0.0", port=port, debug=debug) 