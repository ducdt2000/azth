package main

import (
	"github.com/ducdt2000/azth/backend/internal/fx"
)

// @title AZTH SSO & OIDC Server API
// @version 1.0
// @description Multi-tenant SSO and OIDC server with user management
// @termsOfService http://azth.ducdt.dev/terms/
// @contact.name API Support
// @contact.url http://azth.ducdt.dev/support
// @contact.email support@ducdt.dev
// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
func main() {
	// Create FX application with all dependencies wired together
	app := fx.NewApp()

	// Run the application
	app.Run()
}
