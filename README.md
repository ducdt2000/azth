# AZTH - Multi-Tenant SSO & OIDC Server

A comprehensive Single Sign-On (SSO) and OpenID Connect (OIDC) server with multi-tenant support, built with Echo (Go) backend and Nuxt 3 frontend.

## Features

### 🔐 Authentication & Authorization

- **OpenID Connect (OIDC)** server implementation
- **JWT token** management with RS256 signing
- **Multi-factor authentication** (MFA) support
- **Session management** with secure cookie handling
- **Role-based access control** (RBAC)

### 🏢 Multi-Tenant Architecture

- **Tenant isolation** with separate databases/schemas
- **Custom branding** per tenant
- **Tenant-specific** authentication flows
- **Resource quotas** and usage monitoring

### 👥 User Management

- **User registration** and profile management
- **Email verification** and password reset
- **User groups** and role assignments
- **Account lockout** and security policies
- **Audit logging** for all user activities

### 🛠️ Admin Dashboard

- **Tenant management** interface
- **User administration** panel
- **System monitoring** and analytics
- **Configuration management**
- **Audit trail** visualization

## Tech Stack

### Backend

- **Go** with Echo framework
- **Multiple SQL databases** (PostgreSQL, MySQL, SQLite, SQL Server)
- **Redis** for sessions and caching (with local KV store fallback)
- **OpenTelemetry** for observability
- **JWT** for token management

### Frontend

- **Nuxt 3** with TypeScript
- **Nuxt UI** component library
- **Tailwind CSS** for styling
- **Pinia** for state management
- **VueUse** for utilities

## Project Structure

```
├── backend/                 # Go backend services
│   ├── cmd/                # Application entrypoints
│   ├── internal/           # Core application logic
│   │   ├── config/         # Configuration management
│   │   ├── db/             # Database layer (multi-driver support)
│   │   ├── kv/             # Key-value store (Redis/Local)
│   │   ├── domain/         # Domain models
│   │   └── server/         # HTTP server implementation
│   ├── pkg/                # Shared utilities
│   ├── api/                # REST API handlers
│   ├── configs/            # Configuration files
│   └── test/               # Test utilities
├── frontend/               # Nuxt 3 frontend
│   ├── components/         # Vue components
│   ├── pages/              # Application pages
│   ├── composables/        # Reusable logic
│   ├── middleware/         # Route middleware
│   └── server/             # Server API routes
├── docs/                   # Documentation
├── scripts/                # Build and deployment scripts
├── docker-compose.yml      # Development environment
├── env.example             # Environment variables example
├── DOCKER.md               # Docker deployment guide
└── backend/ENV.md          # Environment variables documentation
```

## Quick Start

### Prerequisites

- Go 1.21+
- Node.js 18+
- Database (PostgreSQL, MySQL, SQLite, or SQL Server)
- Redis (optional - uses local KV store fallback)
- Docker & Docker Compose

### Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/ducdt2000/azth.git
   cd azth
   ```

2. **Configure environment**

   ```bash
   cp env.example .env
   # Edit .env file with your configuration
   ```

3. **Start with Docker Compose**

   ```bash
   # Start with PostgreSQL (default)
   docker-compose --profile all up -d

   # Or start with MySQL
   docker-compose --env-file .env.mysql --profile mysql --profile backend up -d

   # Or start with SQLite (no external database required)
   AZTH_DATABASE_DRIVER=sqlite3 docker-compose --profile backend up backend
   ```

4. **Manual setup** (optional)

   ```bash
   # Backend
   cd backend
   go mod download
   go run cmd/server/main.go

   # Frontend (in another terminal)
   cd frontend
   npm install
   npm run dev
   ```

### Access Applications

- **Backend API**: http://localhost:8080
- **Frontend**: http://localhost:3000
- **API Documentation**: http://localhost:8080/swagger
- **Grafana Dashboard**: http://localhost:3001 (admin/admin)
- **Jaeger Tracing**: http://localhost:16686

## Configuration

### Environment Variables

For comprehensive environment variable documentation, see [backend/ENV.md](backend/ENV.md).

Quick configuration examples:

**PostgreSQL (default)**

```bash
AZTH_DATABASE_DRIVER=postgres
AZTH_DATABASE_HOST=localhost
AZTH_DATABASE_PORT=5432
AZTH_DATABASE_USER=azth
AZTH_DATABASE_PASSWORD=azth
AZTH_DATABASE_NAME=azth
```

**MySQL**

```bash
AZTH_DATABASE_DRIVER=mysql
AZTH_DATABASE_HOST=localhost
AZTH_DATABASE_PORT=3306
AZTH_DATABASE_USER=azth
AZTH_DATABASE_PASSWORD=azth
AZTH_DATABASE_NAME=azth
```

**SQLite (embedded)**

```bash
AZTH_DATABASE_DRIVER=sqlite3
AZTH_DATABASE_SQLITE_FILE=./data/azth.db
AZTH_REDIS_ENABLED=false  # Use local KV store
```

### Docker Deployment

For detailed Docker setup and deployment instructions, see [DOCKER.md](DOCKER.md).

## Database Support

The application supports multiple SQL databases:

| Database   | Driver      | Status  | Notes                         |
| ---------- | ----------- | ------- | ----------------------------- |
| PostgreSQL | `postgres`  | ✅ Full | Recommended for production    |
| MySQL      | `mysql`     | ✅ Full | Full feature support          |
| SQLite     | `sqlite3`   | ✅ Full | Great for development/testing |
| SQL Server | `sqlserver` | ✅ Full | Enterprise support            |

## Storage Options

### Redis (Recommended)

- Full-featured caching and session storage
- Supports clustering for high availability
- Configurable connection pooling

### Local KV Store (Fallback)

- Automatic fallback when Redis is unavailable
- In-memory or file-based storage
- Compatible with Redis interface
- Perfect for development and small deployments

## API Documentation

The API documentation is available at:

- **OpenAPI Spec**: `http://localhost:8080/swagger`
- **Redoc**: `http://localhost:8080/redoc`

## Observability

Built-in support for:

- **Distributed Tracing** with Jaeger
- **Metrics Collection** with Prometheus
- **Dashboards** with Grafana
- **Structured Logging** with configurable levels
- **Health Checks** for all services

Enable observability:

```bash
AZTH_TELEMETRY_TRACING_ENABLED=true
AZTH_TELEMETRY_METRICS_ENABLED=true
docker-compose --profile all --profile observability up -d
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Documentation

- **[Environment Variables](backend/ENV.md)** - Comprehensive configuration guide
- **[Docker Setup](DOCKER.md)** - Docker deployment and configuration
- **[Architecture](docs/ARCHITECTURE.md)** - System architecture and design
- **[Security](SECURITY.md)** - Security guidelines and best practices

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
