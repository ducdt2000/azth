package main

import (
	"fmt"
	"log"
	"time"

	"github.com/ducdt2000/azth/backend/internal/modules/auth/dto"
	"github.com/ducdt2000/azth/backend/internal/modules/auth/service"
	"github.com/ducdt2000/azth/backend/pkg/utils"
	"github.com/google/uuid"
)

// Example demonstrating both authentication modes
func main() {
	fmt.Println("=== Authentication Modes Example ===")

	// Example 1: Stateful Mode Configuration
	fmt.Println("\n1. Stateful Mode (Session-based) Configuration:")
	statefulConfig := &service.AuthConfig{
		Mode:                  service.AuthModeStateful,
		SessionTTL:            24 * time.Hour,
		RefreshTokenTTL:       30 * 24 * time.Hour,
		MaxLoginAttempts:      5,
		LockoutDuration:       15 * time.Minute,
		PasswordHashAlgorithm: service.PasswordHashArgon2ID,
		Argon2IDMemory:        64 * 1024,
		Argon2IDIterations:    3,
		Argon2IDParallelism:   2,
		Argon2IDSaltLength:    16,
		Argon2IDKeyLength:     32,
	}
	fmt.Printf("Mode: %s\n", statefulConfig.Mode)
	fmt.Printf("Session TTL: %v\n", statefulConfig.SessionTTL)
	fmt.Printf("Password Algorithm: %s\n", statefulConfig.PasswordHashAlgorithm)

	// Example 2: Stateless Mode Configuration
	fmt.Println("\n2. Stateless Mode (JWT-based) Configuration:")
	statelessConfig := &service.AuthConfig{
		Mode:                  service.AuthModeStateless,
		JWTSecret:             "your-super-secret-jwt-key-256-bits-long",
		JWTAccessTokenTTL:     15 * time.Minute,
		JWTRefreshTokenTTL:    7 * 24 * time.Hour,
		JWTIssuer:             "azth-auth-service",
		JWTAudience:           "azth-api",
		PasswordHashAlgorithm: service.PasswordHashArgon2ID,
		Argon2IDMemory:        128 * 1024, // 128MB for production
		Argon2IDIterations:    4,
		Argon2IDParallelism:   4,
		Argon2IDSaltLength:    16,
		Argon2IDKeyLength:     32,
	}
	fmt.Printf("Mode: %s\n", statelessConfig.Mode)
	fmt.Printf("JWT Access Token TTL: %v\n", statelessConfig.JWTAccessTokenTTL)
	fmt.Printf("JWT Issuer: %s\n", statelessConfig.JWTIssuer)

	// Example 3: Password Hashing Examples
	fmt.Println("\n3. Password Hashing Examples:")

	password := "MySecurePassword123!"

	// Argon2ID hashing
	fmt.Println("\nArgon2ID Hashing:")
	argonConfig := &utils.Argon2IDConfig{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}

	argonHash, err := utils.HashPassword(password, utils.PasswordHashArgon2ID, argonConfig)
	if err != nil {
		log.Printf("Argon2ID hashing error: %v", err)
	} else {
		fmt.Printf("Argon2ID Hash: %s\n", argonHash)
		fmt.Printf("Verification: %v\n", utils.VerifyPassword(password, argonHash))
	}

	// Bcrypt hashing
	fmt.Println("\nBcrypt Hashing:")
	bcryptHash, err := utils.HashPassword(password, utils.PasswordHashBcrypt, 12)
	if err != nil {
		log.Printf("Bcrypt hashing error: %v", err)
	} else {
		fmt.Printf("Bcrypt Hash: %s\n", bcryptHash)
		fmt.Printf("Verification: %v\n", utils.VerifyPassword(password, bcryptHash))
	}

	// Example 4: JWT Token Generation
	fmt.Println("\n4. JWT Token Generation Example:")
	jwtConfig := &utils.JWTConfig{
		Secret:          statelessConfig.JWTSecret,
		Issuer:          statelessConfig.JWTIssuer,
		Audience:        statelessConfig.JWTAudience,
		AccessTokenTTL:  statelessConfig.JWTAccessTokenTTL,
		RefreshTokenTTL: statelessConfig.JWTRefreshTokenTTL,
	}

	// Generate access token
	accessToken, err := utils.GenerateAccessToken(
		jwtConfig,
		mustParseUUID("550e8400-e29b-41d4-a716-446655440000"), // userID
		mustParseUUID("550e8400-e29b-41d4-a716-446655440001"), // tenantID
		"user@example.com",
		"johndoe",
		"192.168.1.1",
		"Mozilla/5.0 (Example Browser)",
	)
	if err != nil {
		log.Printf("JWT generation error: %v", err)
	} else {
		fmt.Printf("Access Token: %s...\n", accessToken[:50])

		// Validate the token
		claims, err := utils.ValidateJWT(jwtConfig, accessToken)
		if err != nil {
			log.Printf("JWT validation error: %v", err)
		} else {
			fmt.Printf("Token valid! User ID: %s, Email: %s\n", claims.UserID, claims.Email)
		}
	}

	// Example 5: Login Response Examples
	fmt.Println("\n5. Login Response Examples:")

	// Stateful mode response
	fmt.Println("\nStateful Mode Login Response:")
	statefulResponse := &dto.LoginResponse{
		AccessToken:  "session_token_abc123",
		RefreshToken: "refresh_token_def456",
		TokenType:    "Bearer",
		ExpiresIn:    86400, // 24 hours
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		User: dto.UserInfo{
			ID:       mustParseUUID("550e8400-e29b-41d4-a716-446655440000"),
			Email:    "user@example.com",
			Username: "johndoe",
		},
		Session: &dto.SessionInfo{
			ID:           mustParseUUID("550e8400-e29b-41d4-a716-446655440002"),
			IPAddress:    "192.168.1.1",
			UserAgent:    "Mozilla/5.0 (Example Browser)",
			LastActivity: time.Now(),
			ExpiresAt:    time.Now().Add(24 * time.Hour),
			CreatedAt:    time.Now(),
		},
	}
	fmt.Printf("Token Type: %s\n", statefulResponse.TokenType)
	fmt.Printf("Expires In: %d seconds\n", statefulResponse.ExpiresIn)
	fmt.Printf("Has Session: %v\n", statefulResponse.Session != nil)

	// Stateless mode response
	fmt.Println("\nStateless Mode Login Response:")
	statelessResponse := &dto.LoginResponse{
		AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
		RefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 minutes
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		User: dto.UserInfo{
			ID:       mustParseUUID("550e8400-e29b-41d4-a716-446655440000"),
			Email:    "user@example.com",
			Username: "johndoe",
		},
		Session: nil, // No session in JWT mode
	}
	fmt.Printf("Token Type: %s\n", statelessResponse.TokenType)
	fmt.Printf("Expires In: %d seconds\n", statelessResponse.ExpiresIn)
	fmt.Printf("Has Session: %v\n", statelessResponse.Session != nil)

	fmt.Println("\n=== Example Complete ===")
}

// Helper function to parse UUID (for example purposes)
func mustParseUUID(s string) uuid.UUID {
	u, err := uuid.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// Example configuration loading function
func LoadAuthConfigFromEnvironment() *service.AuthConfig {
	config := service.DefaultAuthConfig()

	// Override with environment variables
	if mode := getEnv("AUTH_MODE", "stateful"); mode == "stateless" {
		config.Mode = service.AuthModeStateless
	}

	if secret := getEnv("JWT_SECRET", ""); secret != "" {
		config.JWTSecret = secret
	}

	if algo := getEnv("PASSWORD_ALGORITHM", "argon2id"); algo == "bcrypt" {
		config.PasswordHashAlgorithm = service.PasswordHashBcrypt
	}

	return config
}

// Helper function to get environment variable with default
func getEnv(key, defaultValue string) string {
	// In a real application, use os.Getenv(key)
	// For this example, we'll just return the default
	return defaultValue
}

// Example middleware usage in Echo
/*
func setupAuthMiddleware(e *echo.Echo, authService service.AuthService, logger *logger.Logger) {
	authMiddleware := middleware.NewAuthMiddleware(authService, logger)

	// Public routes (no authentication required)
	public := e.Group("/api/v1")
	public.POST("/auth/login", authHandler.Login)
	public.POST("/auth/register", authHandler.Register)

	// Protected routes (authentication required)
	protected := e.Group("/api/v1")
	protected.Use(authMiddleware.RequireAuth())
	protected.GET("/profile", userHandler.GetProfile)
	protected.POST("/auth/logout", authHandler.Logout)
	protected.GET("/auth/sessions", authHandler.GetSessions) // Only works in stateful mode

	// Optional authentication routes
	optional := e.Group("/api/v1")
	optional.Use(authMiddleware.OptionalAuth())
	optional.GET("/public-data", dataHandler.GetPublicData)
}
*/
