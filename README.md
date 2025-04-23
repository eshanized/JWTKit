# <div align="center"><img src="frontend/public/logo.svg" alt="JWTKit Logo" width="120"/></div>

<h1 align="center">JWTKit</h1>
<p align="center">Web-Based JWT Attacker & Analyzer Toolkit</p>

<p align="center">
  <img src="https://img.shields.io/badge/features-8+-4361EE" alt="Features"/>
  <img src="https://img.shields.io/badge/setup-easy-0BB37E" alt="Setup"/>
  <img src="https://img.shields.io/badge/license-MIT-4CC9F0" alt="License"/>
  <img src="https://img.shields.io/badge/version-1.0.0-F9A826" alt="Version"/>
  <img src="https://img.shields.io/badge/react-%5E18.0.0-61DAFB" alt="React"/>
  <img src="https://img.shields.io/badge/python-%5E3.8-3776AB" alt="Python"/>
</p>

<p align="center">
  <a href="#-project-summary">Summary</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-tech-stack">Tech Stack</a> •
  <a href="#-getting-started">Installation</a> •
  <a href="#%EF%B8%8F-legal-disclaimer">Disclaimer</a> •
  <a href="#-license">License</a>
</p>

---

## 📋 Project Summary

**JWTKit** is a powerful, web-based offensive security toolkit designed to analyze, manipulate, and exploit JSON Web Tokens (JWTs) — one of the most widely used authentication mechanisms in modern web applications. Built for ethical hackers, penetration testers, and security researchers, JWTKit helps uncover misconfigurations and vulnerabilities in token-based systems.

## ✨ Key Features

<table>
  <tr>
    <td width="50%">
      <h3>🔍 JWT Decoder & Inspector</h3>
      <p>Decode and analyze JWT structure with intuitive visualization of header, payload, and signature.</p>
    </td>
    <td width="50%">
      <h3>🛡️ Vulnerability Scanner</h3>
      <p>Automatically detect common JWT security issues including algorithm weaknesses, missing claims, and expiration problems.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>✅ Signature Verifier</h3>
      <p>Verify token signatures with various algorithms and key formats.</p>
    </td>
    <td width="50%">
      <h3>🔄 Algorithm Confusion Tester</h3>
      <p>Test for algorithm confusion vulnerabilities that can lead to signature bypass.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🔨 Brute-Force Engine</h3>
      <p>Attempt to crack weak JWT secrets using wordlists and intelligent analysis.</p>
    </td>
    <td width="50%">
      <h3>✏️ Payload Editor</h3>
      <p>Modify token contents and claims with an intuitive interface.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🧪 Token Tester</h3>
      <p>Verify exploitability against real endpoints with customizable requests.</p>
    </td>
    <td width="50%">
      <h3>⏱️ Time Manipulation Tool</h3>
      <p>Bypass token expiration constraints by modifying timestamps.</p>
    </td>
  </tr>
</table>

Additional features:
- 📚 **Payload Template Library**: Common attack patterns
- 📝 **Pentest Report Generator**: Document findings professionally
- 🔌 **REST API Mode**: Automate JWT testing workflows
- 👥 **Multi-User Dashboard**: Team collaboration (optional)

## 🧱 Tech Stack

<div align="center">
  <table>
    <tr>
      <td align="center" width="96">
        <img src="https://img.icons8.com/color/48/000000/react-native.png" width="48" height="48" alt="React" />
        <br>React
      </td>
      <td align="center" width="96">
        <img src="https://img.icons8.com/color/48/000000/python.png" width="48" height="48" alt="Python" />
        <br>Python
      </td>
      <td align="center" width="96">
        <img src="https://img.icons8.com/color/48/000000/bootstrap.png" width="48" height="48" alt="Bootstrap" />
        <br>Bootstrap
      </td>
    </tr>
    <tr>
      <td align="center" width="96">
        <img src="https://img.icons8.com/color/48/000000/javascript.png" width="48" height="48" alt="JavaScript" />
        <br>JavaScript
      </td>
      <td align="center" width="96">
        <img src="https://img.icons8.com/ios-filled/50/000000/flask.png" width="48" height="48" alt="Flask" />
        <br>Flask
      </td>
      <td align="center" width="96">
        <img src="https://img.icons8.com/color/48/000000/database-restore.png" width="48" height="48" alt="SQLite" />
        <br>SQLite
      </td>
    </tr>
  </table>
</div>

## 🚀 Getting Started

### Prerequisites

- Node.js (v14+)
- Python (v3.8+)
- npm or yarn

### Installation

<details>
<summary><b>1. Clone the repository</b></summary>

```bash
git clone https://github.com/eshanized/JWTKit.git
cd JWTKit
```
</details>

<details>
<summary><b>2. Set up the backend</b></summary>

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```
</details>

<details>
<summary><b>3. Set up the frontend</b></summary>

```bash
cd ../frontend
npm install
```
</details>

<details>
<summary><b>4. Start the development servers</b></summary>

**Backend:**
```bash
cd backend
python main.py
```

**Frontend:**
```bash
cd frontend
npm start
```
</details>

<details>
<summary><b>5. Access the application</b></summary>

Open your browser and navigate to `http://localhost:3000`
</details>

## ⚠️ Legal Disclaimer

**JWTKit** is developed for **educational and authorized penetration testing purposes only**. Unauthorized use against systems without permission is illegal and unethical.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

<div align="center">
  <p>Made with ❤️ by security enthusiasts, for security enthusiasts</p>
  <sub>Copyright © 2025 - present</sub>
</div> 