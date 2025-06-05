#!/bin/bash

# AZTH Development Docker Startup Script
set -e

echo "🚀 Starting AZTH Development Environment with Docker..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED}❌ Docker is not running. Please start Docker and try again.${NC}"
        exit 1
    fi
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker Compose is not available. Please install Docker Compose and try again.${NC}"
        exit 1
    fi
}

# Stop any existing containers
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up existing containers...${NC}"
    docker compose down --remove-orphans 2>/dev/null || true
}

# Start infrastructure services first
start_infrastructure() {
    echo -e "${BLUE}🗄️  Starting infrastructure services (PostgreSQL, Redis)...${NC}"
    docker compose up -d postgres redis
    
    echo -e "${YELLOW}⏳ Waiting for database to be ready...${NC}"
    sleep 10
    
    # Wait for PostgreSQL to be healthy
    while ! docker compose exec postgres pg_isready -U azth > /dev/null 2>&1; do
        echo -e "${YELLOW}⏳ Waiting for PostgreSQL...${NC}"
        sleep 2
    done
    echo -e "${GREEN}✅ PostgreSQL is ready${NC}"
    
    # Wait for Redis to be healthy
    while ! docker compose exec redis redis-cli ping > /dev/null 2>&1; do
        echo -e "${YELLOW}⏳ Waiting for Redis...${NC}"
        sleep 2
    done
    echo -e "${GREEN}✅ Redis is ready${NC}"
}

# Start backend service
start_backend() {
    echo -e "${BLUE}🔧 Building and starting backend service...${NC}"
    docker compose up -d --build backend
    
    echo -e "${YELLOW}⏳ Waiting for backend to be ready...${NC}"
    sleep 5
    
    # Wait for backend to be healthy
    max_attempts=30
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -s http://localhost:8080/health > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Backend is ready${NC}"
            break
        fi
        echo -e "${YELLOW}⏳ Waiting for backend... (attempt $((attempt + 1))/$max_attempts)${NC}"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    if [ $attempt -eq $max_attempts ]; then
        echo -e "${YELLOW}⚠️  Backend might not be fully ready, but continuing...${NC}"
    fi
}

# Start frontend service
start_frontend() {
    echo -e "${BLUE}🎨 Building and starting frontend service...${NC}"
    docker compose up -d --build frontend
    
    echo -e "${YELLOW}⏳ Waiting for frontend to be ready...${NC}"
    sleep 10
    
    # Wait for frontend to be ready
    max_attempts=30
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -s http://localhost:3000 > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Frontend is ready${NC}"
            break
        fi
        echo -e "${YELLOW}⏳ Waiting for frontend... (attempt $((attempt + 1))/$max_attempts)${NC}"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    if [ $attempt -eq $max_attempts ]; then
        echo -e "${YELLOW}⚠️  Frontend might not be fully ready, but continuing...${NC}"
    fi
}

# Start optional services based on profiles
start_optional_services() {
    echo -e "${BLUE}📊 Starting optional services...${NC}"
    
    # Start observability stack if requested
    if [[ "${1}" == *"observability"* ]]; then
        echo -e "${BLUE}📈 Starting observability services (Jaeger, Prometheus, Grafana)...${NC}"
        docker compose --profile observability up -d jaeger prometheus grafana
    fi
    
    # Start development tools if requested
    if [[ "${1}" == *"development"* ]]; then
        echo -e "${BLUE}📧 Starting development services (MailHog)...${NC}"
        docker compose --profile development up -d mailhog
    fi
    
    # Start storage services if requested
    if [[ "${1}" == *"storage"* ]]; then
        echo -e "${BLUE}🗃️  Starting storage services (MinIO)...${NC}"
        docker compose --profile storage up -d minio
    fi
}

# Show service status
show_status() {
    echo -e "\n${GREEN}🎉 AZTH Development Environment is running!${NC}"
    echo -e "\n${BLUE}📋 Service URLs:${NC}"
    echo -e "   🎨 Frontend:    ${GREEN}http://localhost:3000${NC}"
    echo -e "   🔧 Backend:     ${GREEN}http://localhost:8080${NC}"
    echo -e "   🗄️  PostgreSQL:  ${GREEN}localhost:5432${NC} (user: azth, db: azth)"
    echo -e "   🔴 Redis:       ${GREEN}localhost:6379${NC}"
    
    if docker compose ps | grep -q jaeger; then
        echo -e "   🔍 Jaeger:      ${GREEN}http://localhost:16686${NC}"
    fi
    
    if docker compose ps | grep -q prometheus; then
        echo -e "   📊 Prometheus:  ${GREEN}http://localhost:9090${NC}"
    fi
    
    if docker compose ps | grep -q grafana; then
        echo -e "   📈 Grafana:     ${GREEN}http://localhost:3001${NC} (admin/admin)"
    fi
    
    if docker compose ps | grep -q mailhog; then
        echo -e "   📧 MailHog:     ${GREEN}http://localhost:8025${NC}"
    fi
    
    if docker compose ps | grep -q minio; then
        echo -e "   🗃️  MinIO:       ${GREEN}http://localhost:9001${NC} (azth/azthsecret)"
    fi
    
    echo -e "\n${BLUE}📊 Container Status:${NC}"
    docker compose ps
    
    echo -e "\n${YELLOW}📝 Logs:${NC}"
    echo -e "   View all logs:      ${GREEN}docker compose logs -f${NC}"
    echo -e "   View backend logs:  ${GREEN}docker compose logs -f backend${NC}"
    echo -e "   View frontend logs: ${GREEN}docker compose logs -f frontend${NC}"
    
    echo -e "\n${YELLOW}🛑 To stop all services:${NC}"
    echo -e "   ${GREEN}docker compose down${NC}"
}

# Main execution
main() {
    local profiles="${1:-core}"
    
    echo -e "${BLUE}🔧 Profile: ${profiles}${NC}"
    
    check_docker
    check_docker_compose
    cleanup
    start_infrastructure
    start_backend
    start_frontend
    start_optional_services "$profiles"
    show_status
}

# Handle script arguments
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        "full")
            main "observability,development,storage"
            ;;
        "dev")
            main "development"
            ;;
        "obs")
            main "observability"
            ;;
        "core"|"")
            main "core"
            ;;
        *)
            echo -e "${YELLOW}Usage: $0 [core|dev|obs|full]${NC}"
            echo -e "  core: Start core services only (default)"
            echo -e "  dev:  Start core + development tools"
            echo -e "  obs:  Start core + observability tools"
            echo -e "  full: Start all services"
            exit 1
            ;;
    esac
fi 