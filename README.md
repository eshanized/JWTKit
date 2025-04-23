# 🔐 JWTKit – Web-Based JWT Attacker & Analyzer Toolkit

A comprehensive web-based tool for security professionals to analyze, manipulate, and exploit JSON Web Tokens (JWTs).

## 🎯 Project Summary

**JWTKit** is a powerful, web-based offensive security toolkit designed to analyze, manipulate, and exploit JSON Web Tokens (JWTs) — one of the most widely used authentication mechanisms in modern web applications. Built for ethical hackers, penetration testers, and security researchers, JWTKit helps uncover misconfigurations and vulnerabilities in token-based systems.

## 🚀 Key Features

- **JWT Decoder & Inspector**: Decode and analyze JWT structure
- **Auto Vulnerability Scanner**: Detect common JWT security issues
- **Signature Verifier**: Verify token signatures with provided keys
- **Algorithm Confusion Attacker**: Test for algorithm confusion vulnerabilities
- **Brute-Force Engine**: Attempt to crack weak JWT secrets
- **Payload Editor & Claim Manipulator**: Modify token contents
- **Token Tester**: Verify exploitability against real endpoints
- **Time Manipulation Tool**: Bypass token expiration constraints
- **Payload Template Library**: Common attack patterns
- **Pentest Report Generator**: Document findings professionally
- **REST API Mode**: Automate JWT testing workflows
- **Multi-User Dashboard**: Team collaboration (optional)

## 🧱 Tech Stack

- **Frontend**: React with Tailwind CSS
- **Backend**: FastAPI (Python)
- **Database**: SQLite (for session history)

## 🚀 Getting Started

### Prerequisites

- Node.js (v14+)
- Python (v3.8+)
- npm or yarn

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/JWTKit.git
   cd JWTKit
   ```

2. Set up the backend:
   ```
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Set up the frontend:
   ```
   cd ../frontend
   npm install
   ```

4. Start the development servers:
   - Backend: `cd backend && python main.py`
   - Frontend: `cd frontend && npm start`

5. Open your browser and navigate to `http://localhost:3000`

## ⚠️ Legal Disclaimer

**JWTKit** is developed for **educational and authorized penetration testing purposes only**. Unauthorized use against systems without permission is illegal and unethical.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details. 