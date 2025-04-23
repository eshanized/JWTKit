#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
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
if [ ! -d "flask_env" ]; then
    echo -e "${BLUE}Setting up Python virtual environment...${NC}"
    python3 -m venv flask_env
fi

# Activate virtual environment and install dependencies
echo -e "${BLUE}Installing backend dependencies...${NC}"
source flask_env/bin/activate
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    pip install flask flask-cors pyjwt
fi

# Start backend server in the background
echo -e "${GREEN}Starting backend server...${NC}"
# Use the integrated server for more complete functionality
if [ -f "run_jwtkit.py" ]; then
    python run_jwtkit.py &
# Fallback to other server scripts if available
elif [ -f "backend/main.py" ]; then
    python backend/main.py &
else
    python backend/flask_app.py &
fi
BACKEND_PID=$!

# Install frontend dependencies
echo -e "${BLUE}Installing frontend dependencies...${NC}"
cd frontend
npm install

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
    kill $BACKEND_PID
    kill $FRONTEND_PID
    exit 0
}

# Set trap for SIGINT (Ctrl+C)
trap cleanup SIGINT

# Wait for user to interrupt
wait 