#!/bin/bash

# Auth-POC Deployment Script
# Usage: ./deploy.sh
# This script transfers your project to the remote server

set -e

# Configuration
SERVER_USER="ds95097v"
SERVER_HOST="ramganga.merai.cloud"
SERVER_PORT="7722"
REMOTE_DIR="~/auth-poc"
LOCAL_DIR="$(dirname "$0")/.."

echo "=========================================="
echo "  Auth-POC Deployment Script"
echo "=========================================="
echo ""
echo "Server: ${SERVER_USER}@${SERVER_HOST}:${SERVER_PORT}"
echo "Local:  ${LOCAL_DIR}"
echo ""

# Confirm deployment
read -p "Continue with deployment? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 1
fi

echo ""
echo "Step 1: Creating remote directories..."
ssh -p ${SERVER_PORT} ${SERVER_USER}@${SERVER_HOST} "mkdir -p ${REMOTE_DIR}/backend ${REMOTE_DIR}/supabase/migrations"

echo ""
echo "Step 2: Transferring backend files..."
rsync -avz --progress \
  -e "ssh -p ${SERVER_PORT}" \
  --exclude '.git' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.env' \
  --exclude 'venv' \
  --exclude '.venv' \
  ${LOCAL_DIR}/backend/ \
  ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/backend/

echo ""
echo "Step 3: Transferring Supabase migrations..."
rsync -avz --progress \
  -e "ssh -p ${SERVER_PORT}" \
  ${LOCAL_DIR}/supabase/ \
  ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/supabase/

echo ""
echo "Step 4: Transferring deployment config files..."
scp -P ${SERVER_PORT} ${LOCAL_DIR}/deploy/auth-poc.service ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/auth-poc.service
scp -P ${SERVER_PORT} ${LOCAL_DIR}/deploy/auth-poc.nginx ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/auth-poc.nginx

echo ""
echo "=========================================="
echo "  Deployment Complete!"
echo "=========================================="
echo ""
echo "Next steps on the server:"
echo "1. SSH to server: ssh -p ${SERVER_PORT} ${SERVER_USER}@${SERVER_HOST}"
echo "2. Install Docker: curl -fsSL https://get.docker.com | sh"
echo "3. Install Supabase CLI: npm install -g supabase"
echo "4. Start Supabase: cd ${REMOTE_DIR} && supabase start"
echo "5. Apply migrations: supabase db push"
echo "6. Setup Python venv and install deps"
echo "7. Create .env file with Supabase credentials"
echo "8. Install systemd service"
echo "9. Configure nginx"
echo ""
echo "See DEPLOYMENT_GUIDE.md for detailed instructions."