# AZTH Backend - Go Microservices Platform

> A modern, scalable backend platform built with Go, featuring Clean Architecture, microservices patterns, and comprehensive authentication systems.

## 🚀 Quick Start

```bash
# Clone and setup
git clone <repository-url>
cd azth/backend

# Install dependencies
go mod download

# Setup environment
cp config.yaml.example config.yaml
# Edit config.yaml with your settings

# Run migrations
make migrate-up

# Start the application
make run
```

## 📋 Table of Contents

- [🏗️ Architecture](#architecture)
- [🔧 Setup & Installation](#setup--installation)
- [🛠️ Development](#development)
- [📖 Documentation](#documentation)
- [🔑 Authentication](#authentication)
- [🗃️ Database](#database)
- [🧪 Testing](#testing)
- [🚀 Deployment](#deployment)
- [🤝 Contributing](#contributing)

## 🏗️ Architecture

This project follows **Clean Architecture** principles with:

- **Domain Layer**: Core business entities and rules
- **Application Layer**: Use cases and application services
- **Infrastructure Layer**: External interfaces (DB, HTTP, etc.)
- **Interface Layer**: Controllers, handlers, and DTOs

### Key Patterns

- **Shared Repository Pattern**: Centralized data access interfaces
- **CQRS**: Command Query Responsibility Segregation
- **Dependency Injection**: Using Uber FX
- **Microservices**: Modular service architecture

## 🔧 Setup & Installation

### Prerequisites

- Go 1.21+
- PostgreSQL 13+
- Redis 6+
- Docker & Docker Compose (optional)

### Environment Setup

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd azth/backend
   ```

2. **Install dependencies**

   ```bash
   go mod download
   ```

3. **Configuration**

   ```bash
   cp config.yaml.example config.yaml
   # Edit config.yaml with your database and service settings
   ```

4. **Database setup**

   ```bash
   # Create database
   createdb azth_db

   # Run migrations
   make migrate-up
   ```

5. **Start services**

   ```bash
   # Development mode
   make run-dev

   # Production mode
   make run
   ```

## 🛠️ Development

### Project Structure

```
backend/
├── cmd/                    # Application entrypoints
├── internal/               # Private application code
│   ├── config/            # Configuration management
│   ├── db/                # Database connections
│   ├── domain/            # Domain models and entities
│   ├── fx/                # Dependency injection
│   └── modules/           # Feature modules
│       ├── auth/          # Authentication module
│       ├── user/          # User management
│       ├── tenant/        # Multi-tenancy
│       ├── role/          # Role-based access
│       ├── permission/    # Permission management
│       ├── otp/           # OTP and MFA
│       └── notification/  # Email/SMS notifications
├── pkg/                   # Shared utilities
├── configs/               # Configuration files
├── scripts/               # Build and deployment scripts
└── docs/                  # Documentation
```

### Module Structure

Each module follows a consistent structure:

```
module/
├── handlers/              # HTTP handlers
├── service/               # Business logic
├── repository/            # Data access
├── dto/                   # Data transfer objects
└── cqrs/                  # Command/Query handlers
```

### Make Commands

```bash
make help                  # Show all available commands
make run                   # Run the application
make run-dev              # Run in development mode
make test                 # Run tests
make test-coverage        # Run tests with coverage
make build                # Build the application
make clean                # Clean build artifacts
make migrate-up           # Run database migrations
make migrate-down         # Rollback migrations
make generate             # Generate code (mocks, etc.)
make lint                 # Run linters
make fmt                  # Format code
```

## 📖 Documentation

### Core Documentation

| Document                                       | Description                             |
| ---------------------------------------------- | --------------------------------------- |
| [Architecture Guide](docs/ARCHITECTURE.md)     | System architecture and design patterns |
| [API Documentation](docs/API.md)               | REST API endpoints and usage            |
| [Database Schema](docs/DATABASE.md)            | Database design and relationships       |
| [Authentication Guide](docs/AUTHENTICATION.md) | Auth system overview                    |
| [Configuration Guide](docs/CONFIGURATION.md)   | Environment and config setup            |

### Development Guides

| Document                                     | Description                      |
| -------------------------------------------- | -------------------------------- |
| [Development Setup](docs/DEVELOPMENT.md)     | Local development environment    |
| [Testing Guide](docs/TESTING.md)             | Testing strategies and examples  |
| [Contributing Guide](docs/CONTRIBUTING.md)   | How to contribute to the project |
| [Coding Standards](docs/CODING_STANDARDS.md) | Code style and best practices    |

### Feature Documentation

| Document                                                  | Description                       |
| --------------------------------------------------------- | --------------------------------- |
| [Shared Repository Pattern](SHARED_REPOSITORY_PATTERN.md) | Repository sharing across modules |
| [Multi-tenancy](docs/MULTI_TENANCY.md)                    | Tenant isolation and management   |
| [Error Handling](TYPED_ERROR_SYSTEM.md)                   | Error system and handling         |
| [OTP & MFA](docs/OTP_MFA.md)                              | Two-factor authentication         |
| [Notifications](docs/NOTIFICATIONS.md)                    | Email/SMS notification system     |

### Operational Documentation

| Document                               | Description               |
| -------------------------------------- | ------------------------- |
| [Deployment Guide](docs/DEPLOYMENT.md) | Production deployment     |
| [Monitoring](docs/MONITORING.md)       | Logging and observability |
| [Security](docs/SECURITY.md)           | Security best practices   |
| [Performance](docs/PERFORMANCE.md)     | Performance optimization  |

## 🔑 Authentication

The platform supports multiple authentication modes:

- **Session-based**: Traditional cookie/session authentication
- **JWT-based**: Stateless token authentication
- **Multi-factor**: TOTP, SMS, Email verification
- **OAuth**: External provider integration (planned)

### Features

- ✅ Dual authentication modes (Session/JWT)
- ✅ Multi-factor authentication (MFA)
- ✅ Password reset with email/SMS
- ✅ Account locking and rate limiting
- ✅ Role-based access control (RBAC)
- ✅ Multi-tenant isolation

See [Authentication Guide](docs/AUTHENTICATION.md) for detailed information.

## 🗃️ Database

- **Primary**: PostgreSQL with migrations
- **Cache**: Redis for sessions and caching
- **Patterns**: Repository pattern with shared interfaces
- **Migrations**: Versioned database schema management

### Key Features

- Multi-tenant data isolation
- Soft deletes with audit trails
- Optimized indexes for performance
- Connection pooling and health checks

## 🧪 Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific module tests
go test ./internal/modules/auth/...

# Run integration tests
make test-integration

# Run benchmarks
make benchmark
```

### Testing Strategy

- **Unit Tests**: Individual function testing
- **Integration Tests**: Module interaction testing
- **E2E Tests**: Full workflow testing
- **Benchmarks**: Performance testing

## 🚀 Deployment

### Docker Deployment

```bash
# Build image
docker build -t azth-backend .

# Run with Docker Compose
docker-compose up -d
```

### Production Deployment

```bash
# Build for production
make build-prod

# Deploy using your preferred method
# (Kubernetes, Docker Swarm, etc.)
```

### Environment Variables

Key environment variables:

```bash
# Database
DATABASE_URL=postgres://user:pass@localhost/azth_db
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your-secret-key
SESSION_SECRET=your-session-secret

# Services
PORT=8080
LOG_LEVEL=info
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/CONTRIBUTING.md) for details.

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run linters and tests
6. Submit a pull request

### Development Workflow

1. **Setup**: Follow the development setup guide
2. **Code**: Follow our coding standards
3. **Test**: Add comprehensive tests
4. **Document**: Update relevant documentation
5. **Review**: Submit for code review

## 📊 Project Status

- ✅ **Core Architecture**: Clean Architecture implemented
- ✅ **Authentication**: Dual-mode auth system
- ✅ **Database**: PostgreSQL with migrations
- ✅ **Testing**: Unit and integration tests
- ✅ **Documentation**: Comprehensive docs
- 🚧 **Monitoring**: Observability setup (in progress)
- 🚧 **Kubernetes**: K8s deployment configs (planned)

## 📞 Support

- **Documentation**: Check the docs/ directory
- **Issues**: Create a GitHub issue
- **Discussions**: Use GitHub Discussions
- **Email**: [contact@azth.dev](mailto:contact@azth.dev)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Built with ❤️ using Go and Clean Architecture principles**
