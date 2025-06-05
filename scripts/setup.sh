#!/bin/bash

# AZTH Development Environment Setup Script
set -e

echo "🚀 Setting up AZTH development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed. Please install Docker Compose first.${NC}"
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}⚠️  Go is not installed. Backend development will require Go 1.21+${NC}"
else
    echo -e "${GREEN}✅ Go $(go version | awk '{print $3}') is installed${NC}"
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}⚠️  Node.js is not installed. Frontend development will require Node.js 18+${NC}"
else
    echo -e "${GREEN}✅ Node.js $(node --version) is installed${NC}"
fi

# Create necessary directories
echo -e "${BLUE}📁 Creating project directories...${NC}"
mkdir -p backend/{cmd,internal,pkg,api,configs,test,migrations}
mkdir -p frontend/{components,pages,composables,middleware,server,assets,public}
mkdir -p docs
mkdir -p configs/{grafana,prometheus}

# Create environment files if they don't exist
echo -e "${BLUE}📝 Setting up environment files...${NC}"

# Backend environment file
if [ ! -f backend/.env ]; then
    cat > backend/.env << EOF
# Database Configuration
AZTH_DATABASE_URL=postgres://azth:azth@localhost:5432/azth?sslmode=disable
AZTH_REDIS_URL=redis://localhost:6379/0

# Server Configuration
AZTH_SERVER_ADDRESS=0.0.0.0
AZTH_SERVER_PORT=8080

# JWT Configuration
AZTH_JWT_SECRET=your-super-secret-jwt-key-change-in-production
AZTH_JWT_ALGORITHM=RS256
AZTH_JWT_ISSUER=azth
AZTH_JWT_ACCESS_TOKEN_TTL=15m
AZTH_JWT_REFRESH_TOKEN_TTL=168h

# OIDC Configuration
AZTH_OIDC_ISSUER=http://localhost:8080

# Logger Configuration
AZTH_LOGGER_LEVEL=debug
AZTH_LOGGER_FORMAT=json

# Security Configuration
AZTH_SECURITY_PASSWORD_MIN_LENGTH=8
AZTH_SECURITY_MAX_LOGIN_ATTEMPTS=5
AZTH_SECURITY_LOCKOUT_DURATION=15m
EOF
    echo -e "${GREEN}✅ Created backend/.env${NC}"
fi

# Frontend environment file
if [ ! -f frontend/.env ]; then
    cat > frontend/.env << EOF
# Backend API Configuration
NUXT_PUBLIC_API_BASE_URL=http://localhost:8080

# OIDC Configuration
NUXT_PUBLIC_OIDC_ISSUER=http://localhost:8080
NUXT_PUBLIC_OIDC_CLIENT_ID=azth-frontend

# App Configuration
NUXT_PUBLIC_APP_NAME=AZTH
NUXT_PUBLIC_APP_VERSION=1.0.0

# Development Configuration
NODE_ENV=development
NUXT_HOST=0.0.0.0
NUXT_PORT=3000
EOF
    echo -e "${GREEN}✅ Created frontend/.env${NC}"
fi

# Install backend dependencies
echo -e "${BLUE}📦 Installing backend dependencies...${NC}"
if command -v go &> /dev/null; then
    cd backend
    go mod tidy
    cd ..
    echo -e "${GREEN}✅ Backend dependencies installed${NC}"
else
    echo -e "${YELLOW}⚠️  Skipping backend dependencies (Go not installed)${NC}"
fi

# Install frontend dependencies
echo -e "${BLUE}📦 Installing frontend dependencies...${NC}"
if command -v npm &> /dev/null; then
    cd frontend
    npm install
    cd ..
    echo -e "${GREEN}✅ Frontend dependencies installed${NC}"
else
    echo -e "${YELLOW}⚠️  Skipping frontend dependencies (npm not installed)${NC}"
fi

# Start development services
echo -e "${BLUE}🐳 Starting development services...${NC}"
docker-compose up -d postgres redis

# Wait for services to be ready
echo -e "${BLUE}⏳ Waiting for services to be ready...${NC}"
sleep 10

# Check if services are running
if docker-compose ps | grep -q "postgres.*Up"; then
    echo -e "${GREEN}✅ PostgreSQL is running${NC}"
else
    echo -e "${RED}❌ PostgreSQL failed to start${NC}"
fi

if docker-compose ps | grep -q "redis.*Up"; then
    echo -e "${GREEN}✅ Redis is running${NC}"
else
    echo -e "${RED}❌ Redis failed to start${NC}"
fi

# Generate RSA keys for JWT signing
echo -e "${BLUE}🔐 Generating RSA keys for JWT signing...${NC}"
mkdir -p backend/configs/keys
if command -v openssl &> /dev/null; then
    # Generate private key
    openssl genrsa -out backend/configs/keys/jwt_private.pem 2048
    # Generate public key
    openssl rsa -in backend/configs/keys/jwt_private.pem -pubout -out backend/configs/keys/jwt_public.pem
    echo -e "${GREEN}✅ RSA keys generated${NC}"
else
    echo -e "${YELLOW}⚠️  OpenSSL not found. RSA keys not generated.${NC}"
    echo -e "${YELLOW}    You can generate them manually or use HMAC algorithm.${NC}"
fi

echo -e "${GREEN}🎉 AZTH development environment setup complete!${NC}"
echo ""
echo -e "${BLUE}📋 Next steps:${NC}"
echo -e "  1. Start the backend: ${YELLOW}cd backend && go run cmd/server/main.go${NC}"
echo -e "  2. Start the frontend: ${YELLOW}cd frontend && npm run dev${NC}"
echo -e "  3. Visit: ${YELLOW}http://localhost:3000${NC}"
echo ""
echo -e "${BLUE}🛠️  Available services:${NC}"
echo -e "  • Frontend: ${YELLOW}http://localhost:3000${NC}"
echo -e "  • Backend API: ${YELLOW}http://localhost:8080${NC}"
echo -e "  • PostgreSQL: ${YELLOW}localhost:5432${NC}"
echo -e "  • Redis: ${YELLOW}localhost:6379${NC}"
echo ""
echo -e "${BLUE}📚 Optional services (use profiles):${NC}"
echo -e "  • Observability: ${YELLOW}docker-compose --profile observability up -d${NC}"
echo -e "  • Development tools: ${YELLOW}docker-compose --profile development up -d${NC}"
echo -e "  • Storage: ${YELLOW}docker-compose --profile storage up -d${NC}" 