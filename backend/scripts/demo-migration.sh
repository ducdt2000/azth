#!/bin/bash

# Migration Tool Demo Script
# This script demonstrates the complete functionality of the migration management tool

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Ensure we're in the right directory
if [ ! -f "cmd/migrate/main.go" ]; then
    print_error "Please run this script from the backend directory"
    exit 1
fi

print_header "Migration Tool Demo"
print_info "This demo will show you how to use the migration management tool"

# Build the migration tool
print_header "1. Building Migration Tool"
if go build -o bin/migrate cmd/migrate/main.go; then
    print_success "Migration tool built successfully"
else
    print_error "Failed to build migration tool"
    exit 1
fi

# Show help
print_header "2. Migration Tool Help"
./bin/migrate || true

# Clean up any existing demo migrations
print_header "3. Cleaning Up Previous Demo Files"
rm -f internal/db/migrations/*demo*.sql
print_success "Demo files cleaned up"

# Generate empty migration
print_header "4. Generating Empty Migration"
./bin/migrate -action=generate -name=demo_empty_migration
print_success "Empty migration created"

# Show the empty migration
print_info "Generated empty migration:"
cat internal/db/migrations/*demo_empty_migration.sql

# Generate migration from models
print_header "5. Generating Migration from Domain Models"
./bin/migrate -action=generate -name=demo_schema_from_models -from-models
print_success "Schema migration generated from domain models"

# Show part of the generated migration
print_info "Generated schema migration (first 50 lines):"
head -50 internal/db/migrations/*demo_schema_from_models.sql

# Show model analysis
print_header "6. Domain Model Analysis"
print_info "The tool analyzed the following Go files:"
find internal/domain -name "*.go" -type f | while read file; do
    echo "  - $file ($(wc -l < "$file") lines)"
done

print_info "Domain models found in the codebase:"
./bin/migrate -action=generate -name=temp_analysis -from-models 2>&1 | grep "tables" || true
rm -f internal/db/migrations/*temp_analysis.sql

# Demonstrate different migration operations (without DB)
print_header "7. Migration Operations (Demo - No Database)"
print_warning "The following operations require a database connection:"

print_info "To run migrations:"
echo "  ./bin/migrate -action=up"

print_info "To check migration status:"
echo "  ./bin/migrate -action=status"

print_info "To rollback migrations:"
echo "  ./bin/migrate -action=down"

print_info "To migrate to specific version:"
echo "  ./bin/migrate -action=up -target=003"

print_info "To reset all migrations:"
echo "  ./bin/migrate -action=reset -force"

# Show Makefile integration
print_header "8. Makefile Integration"
print_info "The migration tool is integrated with Make targets:"
echo ""
echo "  make migrate-generate NAME=my_migration     # Generate empty migration"
echo "  make migrate-from-models NAME=my_schema     # Generate from models"
echo "  make migrate-up                             # Run pending migrations"
echo "  make migrate-down                           # Rollback one migration"
echo "  make migrate-status                         # Show migration status"
echo "  make migrate-to VERSION=003                 # Migrate to version"
echo ""
print_info "Run 'make help' to see all available targets"

# Show file structure
print_header "9. Migration File Structure"
print_info "Generated migration files are stored in:"
echo "  internal/db/migrations/"
echo ""
print_info "Generated files in this demo:"
ls -la internal/db/migrations/*demo*.sql | while read line; do
    echo "  $line"
done

# Advanced features demo
print_header "10. Advanced Features"

print_info "Auto-detected field mappings:"
echo "  Go Type              → PostgreSQL Type"
echo "  string               → TEXT"
echo "  int, int32           → INTEGER"
echo "  int64                → BIGINT"
echo "  bool                 → BOOLEAN"
echo "  time.Time            → TIMESTAMP WITH TIME ZONE"
echo "  uuid.UUID            → UUID"
echo "  *Type                → Type (nullable)"
echo "  []Type               → Type[] (array)"
echo "  map[string]interface{} → JSONB"

print_info "Automatic features:"
echo "  ✓ Primary key detection (ID fields)"
echo "  ✓ Foreign key relationships"
echo "  ✓ Table name pluralization"
echo "  ✓ CamelCase → snake_case conversion"
echo "  ✓ Index creation on foreign keys"
echo "  ✓ Nullable field detection"
echo "  ✓ Constraint generation"

# Production recommendations
print_header "11. Production Recommendations"
print_warning "For production use:"
echo ""
echo "1. Always backup your database before running migrations"
echo "2. Test migrations in staging environment first"
echo "3. Use version targeting for controlled deployments"
echo "4. Review generated SQL before applying"
echo "5. Keep migrations small and focused"
echo "6. Never edit existing migration files"
echo ""

# Development workflow
print_header "12. Recommended Development Workflow"
print_info "Typical development workflow:"
echo ""
echo "1. Create/modify domain models in internal/domain/"
echo "2. Generate migration: make migrate-from-models NAME=my_changes"
echo "3. Review generated SQL in internal/db/migrations/"
echo "4. Start database: make db-up"
echo "5. Run migration: make migrate-up"
echo "6. Test your changes"
echo "7. If issues, rollback: make migrate-down"
echo ""

# Clean up demo files
print_header "13. Cleanup"
read -p "Do you want to clean up demo migration files? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f internal/db/migrations/*demo*.sql
    print_success "Demo migration files cleaned up"
else
    print_info "Demo files kept for your review"
fi

print_header "Demo Complete!"
print_success "Migration tool demo completed successfully"
print_info "For more information, see README-migration.md"
print_info "Run 'make help' to see all available commands" 