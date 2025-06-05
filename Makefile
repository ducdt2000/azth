.PHONY: help setup clean build test dev docker-up docker-down backend frontend migrations

# Default target
help: ## Show this help message
	@echo "AZTH - Multi-Tenant SSO & OIDC Server"
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Setup development environment
	@echo "🚀 Setting up development environment..."
	@chmod +x scripts/setup.sh
	@./scripts/setup.sh

clean: ## Clean up development environment
	@echo "🧹 Cleaning up..."
	@docker-compose down -v
	@docker system prune -f

build: ## Build all services
	@echo "🔨 Building services..."
	@docker-compose build

test: ## Run tests
	@echo "🧪 Running tests..."
	@cd backend && go test -v ./...
	@cd frontend && npm run type-check

test-coverage: ## Run tests with coverage
	@echo "🧪 Running tests with coverage..."
	@cd backend && go test -v -cover -coverprofile=coverage.out ./...
	@cd backend && go tool cover -html=coverage.out -o coverage.html

dev: ## Start development environment
	@echo "🚀 Starting development environment..."
	@docker-compose up -d postgres redis
	@echo "✅ Core services started"
	@echo "💡 Run 'make backend' and 'make frontend' in separate terminals"

backend: ## Start backend development server
	@echo "🔧 Starting backend server..."
	@cd backend && go run cmd/server/main.go

frontend: ## Start frontend development server
	@echo "🎨 Starting frontend server..."
	@cd frontend && npm run dev

# Docker commands
docker-up: ## Start all services with Docker
	@echo "🐳 Starting all services..."
	@docker-compose --profile development up -d

docker-down: ## Stop all services
	@echo "🛑 Stopping all services..."
	@docker-compose down

docker-logs: ## View logs from all services
	@docker-compose logs -f

docker-logs-backend: ## View backend logs
	@docker-compose logs -f backend

docker-logs-frontend: ## View frontend logs
	@docker-compose logs -f frontend

# Database commands
db-up: ## Start database services
	@echo "🗄️  Starting database services..."
	@docker-compose up -d postgres redis

db-down: ## Stop database services
	@echo "🗄️  Stopping database services..."
	@docker-compose stop postgres redis

db-reset: ## Reset database (destroy and recreate)
	@echo "🗄️  Resetting database..."
	@docker-compose down postgres
	@docker volume rm azth_postgres_data || true
	@docker-compose up -d postgres
	@sleep 5
	@make migrations-up

db-shell: ## Connect to database shell
	@docker-compose exec postgres psql -U azth -d azth

redis-shell: ## Connect to Redis shell
	@docker-compose exec redis redis-cli

# Migration commands
migrations-create: ## Create new migration (usage: make migrations-create NAME=migration_name)
	@if [ -z "$(NAME)" ]; then echo "❌ Please provide NAME=migration_name"; exit 1; fi
	@cd backend && migrate create -ext sql -dir migrations $(NAME)
	@echo "✅ Migration created: $(NAME)"

migrations-up: ## Run database migrations
	@echo "🔄 Running database migrations..."
	@cd backend && migrate -database "postgres://azth:azth@localhost:5432/azth?sslmode=disable" -path migrations up

migrations-down: ## Rollback last migration
	@echo "🔄 Rolling back last migration..."
	@cd backend && migrate -database "postgres://azth:azth@localhost:5432/azth?sslmode=disable" -path migrations down 1

migrations-reset: ## Reset all migrations
	@echo "🔄 Resetting all migrations..."
	@cd backend && migrate -database "postgres://azth:azth@localhost:5432/azth?sslmode=disable" -path migrations drop -f

# Linting and formatting
lint: ## Run linters
	@echo "🔍 Running linters..."
	@cd backend && golangci-lint run
	@cd frontend && npm run lint

lint-fix: ## Fix linting issues
	@echo "🔧 Fixing linting issues..."
	@cd backend && golangci-lint run --fix
	@cd frontend && npm run lint:fix

format: ## Format code
	@echo "💅 Formatting code..."
	@cd backend && go fmt ./...
	@cd backend && goimports -w .
	@cd frontend && npm run lint:fix

# Security
security-scan: ## Run security scans
	@echo "🔒 Running security scans..."
	@cd backend && gosec ./...
	@cd frontend && npm audit

# Performance
benchmark: ## Run benchmarks
	@echo "⚡ Running benchmarks..."
	@cd backend && go test -bench=. ./...

# Documentation
docs: ## Generate documentation
	@echo "📚 Generating documentation..."
	@cd backend && swag init -g cmd/server/main.go

docs-serve: ## Serve documentation
	@echo "📚 Serving documentation..."
	@echo "Backend API docs: http://localhost:8080/swagger/"

# Monitoring and observability
monitoring-up: ## Start monitoring services
	@echo "📊 Starting monitoring services..."
	@docker-compose --profile observability up -d

monitoring-down: ## Stop monitoring services
	@docker-compose stop jaeger prometheus grafana

# Utilities
install-tools: ## Install development tools
	@echo "🛠️  Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/swaggo/swag/cmd/swag@latest
	@go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

status: ## Check service status
	@echo "📊 Service Status:"
	@docker-compose ps

tail-logs: ## Tail all logs
	@docker-compose logs --tail=100 -f

# Production-like environment
prod-build: ## Build production images
	@echo "🏭 Building production images..."
	@docker-compose -f docker-compose.yml -f docker-compose.prod.yml build

prod-up: ## Start production-like environment
	@echo "🏭 Starting production-like environment..."
	@docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

prod-down: ## Stop production-like environment
	@docker-compose -f docker-compose.yml -f docker-compose.prod.yml down 