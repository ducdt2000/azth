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
- **PostgreSQL** for primary data storage
- **Redis** for sessions and caching
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
└── docker-compose.yml      # Development environment
```

## Quick Start

### Prerequisites

- Go 1.21+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose

### Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/ducdt2000/azth.git
   cd azth
   ```

2. **Start development environment**

   ```bash
   docker-compose up -d
   ```

3. **Backend setup**

   ```bash
   cd backend
   go mod download
   go run cmd/server/main.go
   ```

4. **Frontend setup**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

### Environment Variables

Create `.env` files in both `backend/` and `frontend/` directories:

**Backend (.env)**

```env
DATABASE_URL=postgres://username:password@localhost:5432/azth
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-jwt-secret
OIDC_ISSUER=http://localhost:8080
```

**Frontend (.env)**

```env
NUXT_API_BASE_URL=http://localhost:8080
NUXT_PUBLIC_OIDC_ISSUER=http://localhost:8080
```

## API Documentation

The API documentation is available at:

- **OpenAPI Spec**: `http://localhost:8080/swagger`
- **Redoc**: `http://localhost:8080/redoc`

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Architecture

For detailed architecture documentation, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security

For security-related information, please see [SECURITY.md](SECURITY.md).
