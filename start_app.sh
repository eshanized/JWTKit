#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}   Starting JWTKit - JWT Analysis Tool   ${NC}"
echo -e "${BLUE}=========================================${NC}"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed. Please install Python 3.${NC}"
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}Node.js is not installed. Please install Node.js.${NC}"
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo -e "${RED}npm is not installed. Please install npm.${NC}"
    exit 1
fi

# Create Python virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo -e "${BLUE}Setting up Python virtual environment...${NC}"
    python3 -m venv .venv
fi

# Activate virtual environment and install dependencies
echo -e "${BLUE}Installing backend dependencies...${NC}"
source .venv/bin/activate
pip install -r requirements.txt || pip install werkzeug==2.2.3 flask==2.2.3 flask-cors==3.0.10 pyjwt==2.6.0 python-multipart==0.0.6 cryptography==40.0.2 requests==2.30.0 sqlalchemy==1.4.40 passlib==1.7.4 python-dotenv==1.0.0 flask-jwt-extended==4.4.4 flask-limiter==3.3.1

# Start backend server in the background
echo -e "${GREEN}Starting backend server...${NC}"
python app.py &
BACKEND_PID=$!

# Install frontend dependencies
echo -e "${BLUE}Installing frontend dependencies...${NC}"
cd frontend

# Check if frontend components directory structure exists
if [ ! -d "src/components" ]; then
    echo -e "${YELLOW}Creating missing component directory structure...${NC}"
    mkdir -p src/components/layout
    mkdir -p src/components/tools
    mkdir -p src/context
fi

# Install frontend dependencies if needed
echo -e "${BLUE}Installing dependencies...${NC}"
npm install --legacy-peer-deps

# Start frontend server
echo -e "${GREEN}Starting frontend server...${NC}"
npm start &
FRONTEND_PID=$!

cd ..

echo -e "${GREEN}JWTKit is running!${NC}"
echo -e "${BLUE}- Backend:${NC} http://localhost:8000"
echo -e "${BLUE}- Frontend:${NC} http://localhost:3000"
echo -e "${BLUE}- API Docs:${NC} http://localhost:8000/docs"
echo -e "${BLUE}----------------------------------------${NC}"
echo -e "Press Ctrl+C to stop both servers"

# Function to kill processes when script is interrupted
cleanup() {
    echo -e "${RED}Stopping servers...${NC}"
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    exit 0
}

# Set trap for SIGINT (Ctrl+C)
trap cleanup SIGINT

# Wait for user to interrupt
wait 