#!/bin/bash

# Auth-POC Docker Manual Deployment Script
# Run this script and enter your server password when prompted

set -e

SERVER="ds95097v@ramganga.merai.cloud"
PORT="7722"
REMOTE_DIR="auth-poc-docker"

echo "=========================================="
echo "  Auth-POC Docker Deployment"
echo "=========================================="
echo ""
echo "You will need to enter your server password multiple times."
echo "Password: I@m1337"
echo ""

# Step 1: Create directories
echo "Step 1: Creating directories on server..."
ssh -p $PORT $SERVER "mkdir -p ~/${REMOTE_DIR}/backend/routes"

# Step 2: Transfer Docker files
echo ""
echo "Step 2: Transferring Docker files..."
scp -P $PORT Dockerfile docker-compose.yml .dockerignore .env.example $SERVER:~/${REMOTE_DIR}/

# Step 3: Transfer backend files
echo ""
echo "Step 3: Transferring backend files..."
scp -P $PORT backend/requirements.txt backend/main.py backend/config.py backend/schemas.py backend/snowflake.py backend/supabase_client.py $SERVER:~/${REMOTE_DIR}/backend/

# Step 4: Transfer routes
echo ""
echo "Step 4: Transferring routes..."
scp -P $PORT backend/routes/auth.py $SERVER:~/${REMOTE_DIR}/backend/routes/

echo ""
echo "=========================================="
echo "  Files Transferred Successfully!"
echo "=========================================="
echo ""
echo "Now SSH to your server and run:"
echo ""
echo "  ssh -p $PORT $SERVER"
echo ""
echo "Then on the server:"
echo ""
echo "  cd ~/${REMOTE_DIR}"
echo "  cp .env.example .env"
echo "  nano .env    # Add your Supabase credentials"
echo "  docker compose up -d --build"
echo "  curl http://localhost:8000/"
echo ""