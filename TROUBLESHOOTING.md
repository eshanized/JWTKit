# JWTKit Troubleshooting Guide

## Common Issues and Solutions

### Flask ImportError: cannot import name 'url_quote' from 'werkzeug.urls'

**Problem:**
When running the application, you see an error like:
```
ImportError: cannot import name 'url_quote' from 'werkzeug.urls'
```

**Solution:**
This is caused by incompatibility between Flask and Werkzeug versions. Fix by installing specific compatible versions:

```bash
pip install werkzeug==2.2.3 flask==2.2.3
```

### Missing 'diff' Package in Frontend

**Problem:**
The frontend build fails with:
```
Module not found: Error: Can't resolve 'diff' in '/path/to/frontend/src/components'
```

**Solution:**
Install the missing diff package:

```bash
cd frontend
npm install diff --save
```

## Running the Application

To run the application properly:

1. Use the updated `start.sh` script which has been fixed to use compatible versions
2. Or run the backend and frontend separately:

   **Backend:**
   ```bash
   source flask_env/bin/activate  # Use the virtual environment
   cd backend
   python flask_app.py
   ```

   **Frontend:**
   ```bash
   cd frontend
   npm install  # Make sure all dependencies are installed
   npm start
   ```

## Verifying the Setup

- Backend API should be available at: http://localhost:8000/
- Frontend should be available at: http://localhost:3000/
- API documentation can be accessed at: http://localhost:8000/docs

## Environment

For proper functionality, make sure you have:
- Python 3.x with a virtual environment
- Node.js and npm
- The following Python dependencies with compatible versions:
  - werkzeug==2.2.3
  - flask==2.2.3
  - flask-cors==3.0.10
  - pyjwt==2.6.0
  - python-multipart==0.0.6
  - cryptography==40.0.2
  - requests==2.30.0
  - sqlalchemy==1.4.40
  - passlib==1.7.4
  - python-dotenv==1.0.0 