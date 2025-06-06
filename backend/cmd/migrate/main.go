package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ducdt2000/azth/backend/internal/config"
	"github.com/ducdt2000/azth/backend/internal/db"
	"github.com/ducdt2000/azth/backend/pkg/logger"
	"github.com/ducdt2000/azth/backend/pkg/migrate"
)

func main() {
	var (
		action     = flag.String("action", "", "Migration action: generate, up, down, status, reset, version")
		name       = flag.String("name", "", "Migration name (for generate)")
		target     = flag.String("target", "", "Target version (for up/down)")
		force      = flag.Bool("force", false, "Force migration (skip confirmations)")
		fromModels = flag.Bool("from-models", false, "Generate migration from Go models")
		modelPath  = flag.String("model-path", "internal/domain", "Path to domain models")
	)
	flag.Parse()

	if *action == "" {
		printUsage()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize logger
	logger := logger.New(cfg.Logger.Level, cfg.Logger.Format)

	// Initialize migration manager
	// For generation operations, we don't need a database connection
	var migrator *migrate.Migrator
	if *action == "generate" {
		migrator = migrate.NewMigrator(nil, logger)
	} else {
		// Initialize database connection for other operations
		database, err := db.New(cfg.Database, logger)
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer database.Close()
		migrator = migrate.NewMigrator(database, logger)
	}

	// Execute action
	switch *action {
	case "generate":
		if *name == "" {
			log.Fatal("Migration name is required for generate action")
		}
		err = handleGenerate(migrator, *name, *fromModels, *modelPath)
	case "up":
		err = handleUp(migrator, *target)
	case "down":
		err = handleDown(migrator, *target, *force)
	case "status":
		err = handleStatus(migrator)
	case "reset":
		err = handleReset(migrator, *force)
	case "version":
		err = handleVersion(migrator)
	case "create-tables":
		err = handleCreateTables(migrator, *modelPath)
	default:
		log.Fatalf("Unknown action: %s", *action)
	}

	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
}

func handleGenerate(migrator *migrate.Migrator, name string, fromModels bool, modelPath string) error {
	if fromModels {
		fmt.Printf("Generating migration '%s' from models in %s...\n", name, modelPath)
		return migrator.GenerateFromModels(name, modelPath)
	}
	fmt.Printf("Generating empty migration '%s'...\n", name)
	return migrator.GenerateEmpty(name)
}

func handleUp(migrator *migrate.Migrator, target string) error {
	if target == "" {
		fmt.Println("Running all pending migrations...")
		return migrator.Up()
	}
	fmt.Printf("Migrating up to version %s...\n", target)
	return migrator.UpTo(target)
}

func handleDown(migrator *migrate.Migrator, target string, force bool) error {
	if !force {
		fmt.Print("Are you sure you want to rollback? This may cause data loss. (y/N): ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "y" && confirm != "Y" {
			fmt.Println("Migration cancelled.")
			return nil
		}
	}

	if target == "" {
		fmt.Println("Rolling back one migration...")
		return migrator.Down()
	}
	fmt.Printf("Rolling back to version %s...\n", target)
	return migrator.DownTo(target)
}

func handleStatus(migrator *migrate.Migrator) error {
	fmt.Println("Migration status:")
	return migrator.Status()
}

func handleReset(migrator *migrate.Migrator, force bool) error {
	if !force {
		fmt.Print("Are you sure you want to reset all migrations? This will delete all data. (y/N): ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "y" && confirm != "Y" {
			fmt.Println("Reset cancelled.")
			return nil
		}
	}

	fmt.Println("Resetting all migrations...")
	return migrator.Reset()
}

func handleVersion(migrator *migrate.Migrator) error {
	version, err := migrator.Version()
	if err != nil {
		return err
	}
	fmt.Printf("Current migration version: %d\n", version)
	return nil
}

func handleCreateTables(migrator *migrate.Migrator, modelPath string) error {
	fmt.Printf("Creating tables from models in %s...\n", modelPath)
	return migrator.CreateTablesFromModels(modelPath)
}

func printUsage() {
	fmt.Println("Migration Management Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  migrate -action=<action> [options]")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  generate     Generate a new migration")
	fmt.Println("  up           Run pending migrations")
	fmt.Println("  down         Rollback migrations")
	fmt.Println("  status       Show migration status")
	fmt.Println("  reset        Reset all migrations")
	fmt.Println("  version      Show current version")
	fmt.Println("  create-tables Create tables from models")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -name           Migration name (required for generate)")
	fmt.Println("  -target         Target version for up/down")
	fmt.Println("  -force          Skip confirmations")
	fmt.Println("  -from-models    Generate from Go models")
	fmt.Println("  -model-path     Path to domain models (default: internal/domain)")
	fmt.Println("  -config         Config file path (default: config.yaml)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  migrate -action=generate -name=add_users_table")
	fmt.Println("  migrate -action=generate -name=create_initial_schema -from-models")
	fmt.Println("  migrate -action=up")
	fmt.Println("  migrate -action=down -target=003")
	fmt.Println("  migrate -action=status")
}
