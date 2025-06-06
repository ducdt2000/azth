package migrate

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/ducdt2000/azth/backend/internal/db"
	"github.com/ducdt2000/azth/backend/pkg/logger"
)

// Migrator handles database migrations
type Migrator struct {
	db     *db.DB
	logger *logger.Logger
}

// NewMigrator creates a new migration manager
func NewMigrator(database *db.DB, logger *logger.Logger) *Migrator {
	return &Migrator{
		db:     database,
		logger: logger,
	}
}

// GenerateEmpty generates an empty migration file
func (m *Migrator) GenerateEmpty(name string) error {
	timestamp := time.Now().Format("20060102150405")
	filename := fmt.Sprintf("%s_%s.sql", timestamp, strings.ToLower(strings.ReplaceAll(name, " ", "_")))
	filepath := filepath.Join("internal/db/migrations", filename)

	content := fmt.Sprintf(`-- %s
-- Migration: %s

-- +goose Up
-- Write your migration here


-- +goose Down
-- Write your rollback migration here

`, timestamp, name)

	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create migration file: %w", err)
	}

	m.logger.Info("Migration file created", "file", filepath)
	return nil
}

// GenerateFromModels generates migration from Go domain models
func (m *Migrator) GenerateFromModels(name string, modelPath string) error {
	m.logger.Info("Analyzing models", "path", modelPath)

	// Parse Go files to extract struct definitions
	tables, err := m.parseModels(modelPath)
	if err != nil {
		return fmt.Errorf("failed to parse models: %w", err)
	}

	if len(tables) == 0 {
		return fmt.Errorf("no tables found in model path: %s", modelPath)
	}

	// Generate SQL
	upSQL, downSQL, err := m.generateSQL(tables)
	if err != nil {
		return fmt.Errorf("failed to generate SQL: %w", err)
	}

	// Create migration file
	timestamp := time.Now().Format("20060102150405")
	filename := fmt.Sprintf("%s_%s.sql", timestamp, strings.ToLower(strings.ReplaceAll(name, " ", "_")))
	filepath := filepath.Join("internal/db/migrations", filename)

	content := fmt.Sprintf(`-- %s
-- Migration: %s
-- Auto-generated from models in %s

-- +goose Up
%s

-- +goose Down
%s
`, timestamp, name, modelPath, upSQL, downSQL)

	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create migration file: %w", err)
	}

	m.logger.Info("Migration file created from models",
		"file", filepath,
		"tables", len(tables),
	)
	return nil
}

// Up runs all pending migrations
func (m *Migrator) Up() error {
	if m.db == nil {
		return fmt.Errorf("database connection required for migration operations")
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	if err := goose.Up(m.db.DB.DB, "internal/db/migrations"); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	m.logger.Info("All migrations completed successfully")
	return nil
}

// UpTo runs migrations up to a specific version
func (m *Migrator) UpTo(version string) error {
	if m.db == nil {
		return fmt.Errorf("database connection required for migration operations")
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	versionNum, err := strconv.ParseInt(version, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid version format: %w", err)
	}

	if err := goose.UpTo(m.db.DB.DB, "internal/db/migrations", versionNum); err != nil {
		return fmt.Errorf("failed to migrate to version %s: %w", version, err)
	}

	m.logger.Info("Migration completed", "target_version", version)
	return nil
}

// Down rolls back one migration
func (m *Migrator) Down() error {
	if m.db == nil {
		return fmt.Errorf("database connection required for migration operations")
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	if err := goose.Down(m.db.DB.DB, "internal/db/migrations"); err != nil {
		return fmt.Errorf("failed to rollback migration: %w", err)
	}

	m.logger.Info("Rollback completed successfully")
	return nil
}

// DownTo rolls back to a specific version
func (m *Migrator) DownTo(version string) error {
	if m.db == nil {
		return fmt.Errorf("database connection required for migration operations")
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	versionNum, err := strconv.ParseInt(version, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid version format: %w", err)
	}

	if err := goose.DownTo(m.db.DB.DB, "internal/db/migrations", versionNum); err != nil {
		return fmt.Errorf("failed to rollback to version %s: %w", version, err)
	}

	m.logger.Info("Rollback completed", "target_version", version)
	return nil
}

// Status shows migration status
func (m *Migrator) Status() error {
	if m.db == nil {
		return fmt.Errorf("database connection required for migration operations")
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	if err := goose.Status(m.db.DB.DB, "internal/db/migrations"); err != nil {
		return fmt.Errorf("failed to get migration status: %w", err)
	}

	return nil
}

// Reset resets all migrations
func (m *Migrator) Reset() error {
	if m.db == nil {
		return fmt.Errorf("database connection required for migration operations")
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	if err := goose.Reset(m.db.DB.DB, "internal/db/migrations"); err != nil {
		return fmt.Errorf("failed to reset migrations: %w", err)
	}

	m.logger.Info("All migrations reset successfully")
	return nil
}

// Version gets current migration version
func (m *Migrator) Version() (int64, error) {
	if m.db == nil {
		return 0, fmt.Errorf("database connection required for migration operations")
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return 0, fmt.Errorf("failed to set dialect: %w", err)
	}

	version, err := goose.GetDBVersion(m.db.DB.DB)
	if err != nil {
		return 0, fmt.Errorf("failed to get database version: %w", err)
	}

	return version, nil
}

// CreateTablesFromModels creates tables directly from models (dev only)
func (m *Migrator) CreateTablesFromModels(modelPath string) error {
	if m.db == nil {
		return fmt.Errorf("database connection required for table creation operations")
	}

	m.logger.Warn("CreateTablesFromModels is for development only")

	tables, err := m.parseModels(modelPath)
	if err != nil {
		return fmt.Errorf("failed to parse models: %w", err)
	}

	upSQL, _, err := m.generateSQL(tables)
	if err != nil {
		return fmt.Errorf("failed to generate SQL: %w", err)
	}

	// Execute SQL directly
	ctx := context.Background()
	if _, err := m.db.ExecContext(ctx, upSQL); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	m.logger.Info("Tables created from models", "count", len(tables))
	return nil
}

// TableDefinition represents a database table
type TableDefinition struct {
	Name    string
	Fields  []FieldDefinition
	Indexes []IndexDefinition
}

// FieldDefinition represents a table field
type FieldDefinition struct {
	Name            string
	Type            string
	Nullable        bool
	Default         string
	PrimaryKey      bool
	Unique          bool
	ForeignKey      *ForeignKeyDefinition
	Index           bool
	CheckConstraint string
}

// IndexDefinition represents a table index
type IndexDefinition struct {
	Name   string
	Fields []string
	Unique bool
	Where  string
}

// ForeignKeyDefinition represents a foreign key constraint
type ForeignKeyDefinition struct {
	Table    string
	Column   string
	OnDelete string
	OnUpdate string
}

// parseModels parses Go model files and extracts table definitions
func (m *Migrator) parseModels(modelPath string) ([]TableDefinition, error) {
	var tables []TableDefinition

	err := filepath.WalkDir(modelPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(path, ".go") || d.IsDir() {
			return nil
		}

		fileTables, err := m.parseModelFile(path)
		if err != nil {
			m.logger.Warn("Failed to parse model file", "file", path, "error", err)
			return nil // Continue with other files
		}

		tables = append(tables, fileTables...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return tables, nil
}

// parseModelFile parses a single Go file for struct definitions
func (m *Migrator) parseModelFile(filename string) ([]TableDefinition, error) {
	fileSet := token.NewFileSet()
	node, err := parser.ParseFile(fileSet, filename, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var tables []TableDefinition

	ast.Inspect(node, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}

		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return true
		}

		// Extract table name from struct name
		tableName := m.structToTableName(typeSpec.Name.Name)

		// Skip if struct doesn't look like a database model
		if !m.isModelStruct(structType) {
			return true
		}

		table := TableDefinition{
			Name:   tableName,
			Fields: m.parseStructFields(structType),
		}

		tables = append(tables, table)
		return true
	})

	return tables, nil
}

// isModelStruct determines if a struct represents a database model
func (m *Migrator) isModelStruct(structType *ast.StructType) bool {
	// Check if struct has db tags or common model fields
	hasDBTags := false
	hasModelFields := false

	for _, field := range structType.Fields.List {
		if field.Tag != nil {
			tag := strings.Trim(field.Tag.Value, "`")
			if strings.Contains(tag, `db:"`) {
				hasDBTags = true
			}
		}

		// Check for common model fields
		for _, name := range field.Names {
			fieldName := name.Name
			if fieldName == "ID" || fieldName == "CreatedAt" || fieldName == "UpdatedAt" {
				hasModelFields = true
			}
		}
	}

	// Only consider it a model if it has both db tags AND model fields
	// This filters out DTOs and response structures
	return hasDBTags && hasModelFields
}

// parseStructFields extracts field definitions from struct
func (m *Migrator) parseStructFields(structType *ast.StructType) []FieldDefinition {
	var fields []FieldDefinition

	for _, field := range structType.Fields.List {
		if len(field.Names) == 0 {
			continue // Anonymous field
		}

		for _, name := range field.Names {
			fieldDef := FieldDefinition{
				Name: name.Name,
				Type: m.goTypeToSQLType(field.Type),
			}

			// Parse struct tags
			if field.Tag != nil {
				tag := strings.Trim(field.Tag.Value, "`")
				fieldDef = m.parseFieldTags(fieldDef, tag)
			}

			// Auto-detect primary key
			if fieldDef.Name == "ID" || fieldDef.Name == "id" || name.Name == "ID" {
				fieldDef.PrimaryKey = true
				if fieldDef.Type == "TEXT" {
					fieldDef.Type = "UUID"
				}
			}

			// Set default column name if not set by db tag
			if fieldDef.Name == "" {
				fieldDef.Name = m.camelToSnake(name.Name)
			}

			// Handle nullable types (pointers)
			if strings.HasPrefix(fieldDef.Type, "*") {
				fieldDef.Type = strings.TrimPrefix(fieldDef.Type, "*")
				fieldDef.Nullable = true
			} else if m.isPointerType(field.Type) {
				fieldDef.Nullable = true
			}

			fields = append(fields, fieldDef)
		}
	}

	return fields
}

// parseFieldTags parses struct tags for database information
func (m *Migrator) parseFieldTags(field FieldDefinition, tagString string) FieldDefinition {
	// Parse db tag
	if dbTag := m.extractTag(tagString, "db"); dbTag != "" {
		if dbTag == "-" {
			return field // Skip this field
		}
		field.Name = dbTag
	}

	// Parse json tag for field name if db tag is missing
	if field.Name == "" {
		if jsonTag := m.extractTag(tagString, "json"); jsonTag != "" && jsonTag != "-" {
			field.Name = strings.Split(jsonTag, ",")[0]
		}
	}

	// Check for validation tags that affect database schema
	if validateTag := m.extractTag(tagString, "validate"); validateTag != "" {
		if strings.Contains(validateTag, "required") {
			field.Nullable = false
		}
	}

	return field
}

// extractTag extracts a specific tag value
func (m *Migrator) extractTag(tagString, tagName string) string {
	re := regexp.MustCompile(tagName + `:"([^"]*)"`)
	matches := re.FindStringSubmatch(tagString)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// isPointerType checks if the given expression is a pointer type
func (m *Migrator) isPointerType(expr ast.Expr) bool {
	_, ok := expr.(*ast.StarExpr)
	return ok
}

// goTypeToSQLType converts Go types to PostgreSQL types
func (m *Migrator) goTypeToSQLType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		switch t.Name {
		case "string":
			return "TEXT"
		case "int", "int32":
			return "INTEGER"
		case "int64":
			return "BIGINT"
		case "bool":
			return "BOOLEAN"
		case "float32":
			return "REAL"
		case "float64":
			return "DOUBLE PRECISION"
		case "Time":
			return "TIMESTAMP WITH TIME ZONE"
		}
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok {
			if x.Name == "uuid" && t.Sel.Name == "UUID" {
				return "UUID"
			}
			if x.Name == "time" && t.Sel.Name == "Time" {
				return "TIMESTAMP WITH TIME ZONE"
			}
		}
	case *ast.StarExpr:
		// Pointer type - nullable
		return m.goTypeToSQLType(t.X)
	case *ast.ArrayType:
		elemType := m.goTypeToSQLType(t.Elt)
		return elemType + "[]"
	case *ast.MapType:
		// Map types become JSONB
		return "JSONB"
	case *ast.InterfaceType:
		// interface{} becomes JSONB
		return "JSONB"
	}
	return "TEXT" // Default fallback
}

// structToTableName converts struct name to table name
func (m *Migrator) structToTableName(structName string) string {
	// Convert CamelCase to snake_case and pluralize
	tableName := m.camelToSnake(structName)
	return m.pluralize(tableName)
}

// camelToSnake converts CamelCase to snake_case
func (m *Migrator) camelToSnake(str string) string {
	var result []rune
	for i, r := range str {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result = append(result, '_')
		}
		result = append(result, r)
	}
	return strings.ToLower(string(result))
}

// pluralize adds simple pluralization
func (m *Migrator) pluralize(word string) string {
	// Handle special cases
	switch word {
	case "settings":
		return "settings" // Already plural
	case "metadata":
		return "metadata" // Already plural
	}

	if strings.HasSuffix(word, "y") && len(word) > 1 && !m.isVowel(word[len(word)-2]) {
		return strings.TrimSuffix(word, "y") + "ies"
	}
	if strings.HasSuffix(word, "s") || strings.HasSuffix(word, "sh") || strings.HasSuffix(word, "ch") ||
		strings.HasSuffix(word, "x") || strings.HasSuffix(word, "z") {
		return word + "es"
	}
	if strings.HasSuffix(word, "f") {
		return strings.TrimSuffix(word, "f") + "ves"
	}
	if strings.HasSuffix(word, "fe") {
		return strings.TrimSuffix(word, "fe") + "ves"
	}
	return word + "s"
}

// isVowel checks if a character is a vowel
func (m *Migrator) isVowel(c byte) bool {
	return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u'
}

// generateSQL generates CREATE and DROP SQL statements
func (m *Migrator) generateSQL(tables []TableDefinition) (string, string, error) {
	var upSQL, downSQL strings.Builder

	// Sort tables by dependencies (basic implementation)
	sortedTables := m.sortTablesByDependencies(tables)

	// Generate CREATE statements
	for _, table := range sortedTables {
		createSQL := m.generateCreateTableSQL(table)
		upSQL.WriteString(createSQL)
		upSQL.WriteString("\n\n")
	}

	// Generate DROP statements (reverse order)
	for i := len(sortedTables) - 1; i >= 0; i-- {
		table := sortedTables[i]
		dropSQL := fmt.Sprintf("DROP TABLE IF EXISTS %s;\n", table.Name)
		downSQL.WriteString(dropSQL)
	}

	return upSQL.String(), downSQL.String(), nil
}

// sortTablesByDependencies sorts tables by foreign key dependencies
func (m *Migrator) sortTablesByDependencies(tables []TableDefinition) []TableDefinition {
	// Simple topological sort based on foreign keys
	sorted := make([]TableDefinition, 0, len(tables))
	remaining := make([]TableDefinition, len(tables))
	copy(remaining, tables)

	for len(remaining) > 0 {
		added := false
		for i, table := range remaining {
			if m.hasNoDependencies(table, remaining, sorted) {
				sorted = append(sorted, table)
				remaining = append(remaining[:i], remaining[i+1:]...)
				added = true
				break
			}
		}
		if !added {
			// Circular dependency or unresolved - add remaining tables
			sorted = append(sorted, remaining...)
			break
		}
	}

	return sorted
}

// hasNoDependencies checks if table has no unresolved dependencies
func (m *Migrator) hasNoDependencies(table TableDefinition, remaining []TableDefinition, resolved []TableDefinition) bool {
	for _, field := range table.Fields {
		if field.ForeignKey != nil {
			// Check if referenced table is already resolved
			found := false
			for _, resolvedTable := range resolved {
				if resolvedTable.Name == field.ForeignKey.Table {
					found = true
					break
				}
			}
			if !found {
				// Check if referenced table is in remaining (circular dependency)
				for _, remainingTable := range remaining {
					if remainingTable.Name == field.ForeignKey.Table && remainingTable.Name != table.Name {
						return false
					}
				}
			}
		}
	}
	return true
}

// generateCreateTableSQL generates CREATE TABLE SQL for a table
func (m *Migrator) generateCreateTableSQL(table TableDefinition) string {
	var sql strings.Builder

	sql.WriteString(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n", table.Name))

	// Generate field definitions
	fieldDefs := make([]string, 0, len(table.Fields))
	for _, field := range table.Fields {
		fieldDef := m.generateFieldDefinition(field)
		fieldDefs = append(fieldDefs, "    "+fieldDef)
	}

	sql.WriteString(strings.Join(fieldDefs, ",\n"))
	sql.WriteString("\n);")

	// Generate indexes
	for _, index := range table.Indexes {
		indexSQL := m.generateIndexSQL(table.Name, index)
		sql.WriteString("\n\n")
		sql.WriteString(indexSQL)
	}

	return sql.String()
}

// generateFieldDefinition generates SQL for a single field
func (m *Migrator) generateFieldDefinition(field FieldDefinition) string {
	var parts []string

	parts = append(parts, field.Name)
	parts = append(parts, field.Type)

	if field.PrimaryKey {
		parts = append(parts, "PRIMARY KEY")
		if field.Type == "UUID" {
			parts = append(parts, "DEFAULT gen_random_uuid()")
		}
	}

	if !field.Nullable && !field.PrimaryKey {
		parts = append(parts, "NOT NULL")
	}

	if field.Default != "" {
		parts = append(parts, "DEFAULT", field.Default)
	}

	if field.Unique {
		parts = append(parts, "UNIQUE")
	}

	if field.CheckConstraint != "" {
		parts = append(parts, "CHECK", "("+field.CheckConstraint+")")
	}

	return strings.Join(parts, " ")
}

// generateIndexSQL generates CREATE INDEX SQL
func (m *Migrator) generateIndexSQL(tableName string, index IndexDefinition) string {
	indexType := "INDEX"
	if index.Unique {
		indexType = "UNIQUE INDEX"
	}

	sql := fmt.Sprintf("CREATE %s IF NOT EXISTS %s ON %s (%s)",
		indexType,
		index.Name,
		tableName,
		strings.Join(index.Fields, ", "),
	)

	if index.Where != "" {
		sql += " WHERE " + index.Where
	}

	return sql + ";"
}
