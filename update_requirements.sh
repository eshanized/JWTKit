#!/bin/bash

cat > backend/requirements.txt << 'EOF'
fastapi==0.78.0
uvicorn==0.17.6
pyjwt==2.6.0
python-multipart==0.0.6
pydantic==1.9.1
cryptography==40.0.2
requests==2.30.0
sqlalchemy==2.0.15
passlib==1.7.4
python-dotenv==1.0.0
EOF

echo "Requirements updated successfully!"