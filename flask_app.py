from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def index():
    return jsonify({"status": "healthy", "service": "JWTKit API"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True) 