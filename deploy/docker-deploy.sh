#!/bin/bash

# Auth-POC Docker Deployment Script
# Usage: ./deploy/docker-deploy.sh
# This script transfers your Docker project to the remote server and deploys it

set -e

# Configuration
SERVER_USER="ds95097v"
SERVER_HOST="padma.merai.cloud"
SERVER_PORT="7722"
REMOTE_DIR="~/auth-poc-docker"
LOCAL_DIR="$(dirname "$0")/.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "  Auth-POC Docker Deployment Script"
echo "=========================================="
echo ""
echo -e "${YELLOW}Server:${NC} ${SERVER_USER}@${SERVER_HOST}:${SERVER_PORT}"
echo -e "${YELLOW}Remote Dir:${NC} ${REMOTE_DIR}"
echo ""

# Confirm deployment
read -p "Continue with deployment? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 1
fi

echo ""
echo -e "${GREEN}Step 1: Creating remote directories...${NC}"
ssh -p ${SERVER_PORT} ${SERVER_USER}@${SERVER_HOST} "mkdir -p ${REMOTE_DIR}/backend ${REMOTE_DIR}/backend/routes"

echo ""
echo -e "${GREEN}Step 2: Transferring Docker files...${NC}"
scp -P ${SERVER_PORT} ${LOCAL_DIR}/Dockerfile ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/Dockerfile
scp -P ${SERVER_PORT} ${LOCAL_DIR}/docker-compose.yml ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/docker-compose.yml
scp -P ${SERVER_PORT} ${LOCAL_DIR}/.dockerignore ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/.dockerignore
scp -P ${SERVER_PORT} ${LOCAL_DIR}/.env.example ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/.env.example

echo ""
echo -e "${GREEN}Step 3: Transferring backend files...${NC}"
scp -P ${SERVER_PORT} ${LOCAL_DIR}/backend/requirements.txt ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/backend/
scp -P ${SERVER_PORT} ${LOCAL_DIR}/backend/main.py ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/backend/
scp -P ${SERVER_PORT} ${LOCAL_DIR}/backend/config.py ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/backend/
scp -P ${SERVER_PORT} ${LOCAL_DIR}/backend/schemas.py ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/backend/
scp -P ${SERVER_PORT} ${LOCAL_DIR}/backend/snowflake.py ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/backend/
scp -P ${SERVER_PORT} ${LOCAL_DIR}/backend/supabase_client.py ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/backend/
scp -P ${SERVER_PORT} ${LOCAL_DIR}/backend/routes/auth.py ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/backend/routes/
scp -P ${SERVER_PORT} ${LOCAL_DIR}/backend/email_service.py ${SERVER_USER}@${SERVER_HOST}:${REMOTE_DIR}/backend/

echo ""
echo -e "${GREEN}Step 4: Setting up environment and starting container...${NC}"
ssh -p ${SERVER_PORT} ${SERVER_USER}@${SERVER_HOST} << 'ENDSSH'
cd ~/auth-poc-docker

# Check if .env exists, if not create from example
if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo ""
    echo "=========================================="
    echo "  IMPORTANT: Edit .env file with your credentials!"
    echo "=========================================="
    echo ""
    echo "Run: nano ~/auth-poc-docker/.env"
    echo ""
    echo "Required values:"
    echo "  SUPABASE_URL=your-supabase-url"
    echo "  SUPABASE_SERVICE_ROLE_KEY=your-service-role-key"
    echo "  FRONTEND_ORIGIN=http://localhost:3000"
    echo ""
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Please install Docker first:"
    echo "  curl -fsSL https://get.docker.com | sudo sh"
    echo "  sudo usermod -aG docker $USER"
    exit 1
fi

# Check if container is already running
if docker ps | grep -q auth-poc-backend; then
    echo "Stopping existing container..."
    docker compose down
fi

# Build and start the container
echo "Building and starting Docker container..."
docker compose up -d --build

echo ""
echo "Waiting for container to start..."
sleep 5

# Check if container is running
if docker ps | grep -q auth-poc-backend; then
    echo ""
    echo "=========================================="
    echo "  Deployment Successful!"
    echo "=========================================="
    echo ""
    echo "Container status:"
    docker compose ps
    echo ""
    echo "Test the API:"
    echo "  curl http://localhost:8000/"
    echo ""
else
    echo ""
    echo "=========================================="
    echo "  Deployment Failed!"
    echo "=========================================="
    echo ""
    echo "Check logs with:"
    echo "  docker compose logs"
fi
ENDSSH

echo ""
echo "=========================================="
echo "  Deployment Complete!"
echo "=========================================="
