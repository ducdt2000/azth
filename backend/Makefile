# Azth Backend Makefile

# Variables
MIGRATE_TOOL := ./bin/migrate
MODEL_PATH := internal/domain
MIGRATION_DIR := internal/db/migrations

# Build targets
.PHONY: build
build:
	go build -o bin/app cmd/server/main.go

.PHONY: build-migrate
build-migrate:
	go build -o bin/migrate cmd/migrate/main.go

# Development targets
.PHONY: run
run: build
	./bin/app

.PHONY: test
test:
	go test ./...

.PHONY: test-verbose
test-verbose:
	go test -v ./...

.PHONY: clean
clean:
	rm -rf bin/

# Migration targets
.PHONY: migrate-build
migrate-build: build-migrate

.PHONY: migrate-up
migrate-up: build-migrate
	$(MIGRATE_TOOL) -action=up

.PHONY: migrate-down
migrate-down: build-migrate
	$(MIGRATE_TOOL) -action=down

.PHONY: migrate-status
migrate-status: build-migrate
	$(MIGRATE_TOOL) -action=status

.PHONY: migrate-version
migrate-version: build-migrate
	$(MIGRATE_TOOL) -action=version

.PHONY: migrate-reset
migrate-reset: build-migrate
	$(MIGRATE_TOOL) -action=reset -force

# Migration generation targets
.PHONY: migrate-generate
migrate-generate: build-migrate
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make migrate-generate NAME=migration_name"; \
		exit 1; \
	fi
	$(MIGRATE_TOOL) -action=generate -name=$(NAME)

.PHONY: migrate-from-models
migrate-from-models: build-migrate
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make migrate-from-models NAME=migration_name"; \
		exit 1; \
	fi
	$(MIGRATE_TOOL) -action=generate -name=$(NAME) -from-models -model-path=$(MODEL_PATH)

.PHONY: migrate-create-tables
migrate-create-tables: build-migrate
	$(MIGRATE_TOOL) -action=create-tables -model-path=$(MODEL_PATH)

# Target specific migrations
.PHONY: migrate-to
migrate-to: build-migrate
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make migrate-to VERSION=target_version"; \
		exit 1; \
	fi
	$(MIGRATE_TOOL) -action=up -target=$(VERSION)

.PHONY: migrate-down-to
migrate-down-to: build-migrate
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make migrate-down-to VERSION=target_version"; \
		exit 1; \
	fi
	$(MIGRATE_TOOL) -action=down -target=$(VERSION)

# Docker targets
.PHONY: docker-build
docker-build:
	docker build -t azth-backend .

.PHONY: docker-up
docker-up:
	docker-compose up -d

.PHONY: docker-down
docker-down:
	docker-compose down

.PHONY: docker-logs
docker-logs:
	docker-compose logs -f

# Database targets
.PHONY: db-up
db-up:
	docker-compose up -d postgres redis

.PHONY: db-down
db-down:
	docker-compose stop postgres redis

.PHONY: db-reset
db-reset: db-down
	docker-compose rm -f postgres
	docker volume rm azth_postgres_data || true
	docker-compose up -d postgres
	sleep 5
	make migrate-up

# Development workflow
.PHONY: dev-setup
dev-setup: build-migrate db-up
	sleep 5
	make migrate-up

.PHONY: dev-reset
dev-reset: db-reset

# Linting and formatting
.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint:
	golangci-lint run

# Dependencies
.PHONY: deps
deps:
	go mod download
	go mod tidy

.PHONY: deps-update
deps-update:
	go get -u ./...
	go mod tidy

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  Build:"
	@echo "    build              - Build the main application"
	@echo "    build-migrate      - Build the migration tool"
	@echo "    clean              - Clean build artifacts"
	@echo ""
	@echo "  Development:"
	@echo "    run                - Build and run the application"
	@echo "    test               - Run tests"
	@echo "    test-verbose       - Run tests with verbose output"
	@echo "    dev-setup          - Set up development environment"
	@echo "    dev-reset          - Reset development environment"
	@echo ""
	@echo "  Migration Management:"
	@echo "    migrate-up         - Run all pending migrations"
	@echo "    migrate-down       - Rollback one migration"
	@echo "    migrate-status     - Show migration status"
	@echo "    migrate-version    - Show current migration version"
	@echo "    migrate-reset      - Reset all migrations (DANGER)"
	@echo ""
	@echo "  Migration Generation:"
	@echo "    migrate-generate NAME=name         - Generate empty migration"
	@echo "    migrate-from-models NAME=name      - Generate migration from models"
	@echo "    migrate-create-tables              - Create tables from models (dev)"
	@echo ""
	@echo "  Migration Targeting:"
	@echo "    migrate-to VERSION=version         - Migrate to specific version"
	@echo "    migrate-down-to VERSION=version    - Rollback to specific version"
	@echo ""
	@echo "  Database:"
	@echo "    db-up              - Start database containers"
	@echo "    db-down            - Stop database containers"
	@echo "    db-reset           - Reset database with fresh data"
	@echo ""
	@echo "  Docker:"
	@echo "    docker-build       - Build Docker image"
	@echo "    docker-up          - Start all containers"
	@echo "    docker-down        - Stop all containers"
	@echo "    docker-logs        - Show container logs"
	@echo ""
	@echo "  Code Quality:"
	@echo "    fmt                - Format Go code"
	@echo "    vet                - Run go vet"
	@echo "    lint               - Run golangci-lint"
	@echo ""
	@echo "  Dependencies:"
	@echo "    deps               - Download and tidy dependencies"
	@echo "    deps-update        - Update dependencies"
	@echo ""
	@echo "Examples:"
	@echo "  make migrate-generate NAME=add_user_indexes"
	@echo "  make migrate-from-models NAME=create_initial_schema"
	@echo "  make migrate-to VERSION=003"
	@echo "  make migrate-down-to VERSION=001" 