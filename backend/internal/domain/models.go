package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	TenantID          uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Email             string     `json:"email" db:"email"`
	Username          string     `json:"username" db:"username"`
	PasswordHash      string     `json:"-" db:"password_hash"`
	FirstName         string     `json:"first_name" db:"first_name"`
	LastName          string     `json:"last_name" db:"last_name"`
	Avatar            *string    `json:"avatar" db:"avatar"`
	EmailVerified     bool       `json:"email_verified" db:"email_verified"`
	EmailVerifiedAt   *time.Time `json:"email_verified_at" db:"email_verified_at"`
	PhoneNumber       *string    `json:"phone_number" db:"phone_number"`
	PhoneVerified     bool       `json:"phone_verified" db:"phone_verified"`
	PhoneVerifiedAt   *time.Time `json:"phone_verified_at" db:"phone_verified_at"`
	MFAEnabled        bool       `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret         *string    `json:"-" db:"mfa_secret"`
	BackupCodes       []string   `json:"-" db:"backup_codes"`
	Status            UserStatus `json:"status" db:"status"`
	LastLoginAt       *time.Time `json:"last_login_at" db:"last_login_at"`
	LoginAttempts     int        `json:"-" db:"login_attempts"`
	LockedUntil       *time.Time `json:"-" db:"locked_until"`
	PasswordChangedAt *time.Time `json:"password_changed_at" db:"password_changed_at"`
	Metadata          JSONMap    `json:"metadata" db:"metadata"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt         *time.Time `json:"deleted_at" db:"deleted_at"`
}

// UserStatus represents the status of a user
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusInactive  UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusPending   UserStatus = "pending"
)

// Tenant represents a tenant in the multi-tenant system
type Tenant struct {
	ID             uuid.UUID    `json:"id" db:"id"`
	Name           string       `json:"name" db:"name"`
	Slug           string       `json:"slug" db:"slug"`
	Domain         *string      `json:"domain" db:"domain"`
	LogoURL        *string      `json:"logo_url" db:"logo_url"`
	PrimaryColor   *string      `json:"primary_color" db:"primary_color"`
	SecondaryColor *string      `json:"secondary_color" db:"secondary_color"`
	Status         TenantStatus `json:"status" db:"status"`
	Plan           string       `json:"plan" db:"plan"`
	MaxUsers       int          `json:"max_users" db:"max_users"`
	Settings       JSONMap      `json:"settings" db:"settings"`
	Metadata       JSONMap      `json:"metadata" db:"metadata"`
	CreatedAt      time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at" db:"updated_at"`
	DeletedAt      *time.Time   `json:"deleted_at" db:"deleted_at"`
}

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusInactive  TenantStatus = "inactive"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusTrial     TenantStatus = "trial"
)

// Role represents a role in the RBAC system
type Role struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	TenantID    uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Name        string     `json:"name" db:"name"`
	Slug        string     `json:"slug" db:"slug"`
	Description *string    `json:"description" db:"description"`
	Permissions []string   `json:"permissions" db:"permissions"`
	IsSystem    bool       `json:"is_system" db:"is_system"`
	Metadata    JSONMap    `json:"metadata" db:"metadata"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at" db:"deleted_at"`
}

// UserRole represents the many-to-many relationship between users and roles
type UserRole struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	RoleID    uuid.UUID  `json:"role_id" db:"role_id"`
	TenantID  uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at" db:"deleted_at"`
}

// Session represents a user session
type Session struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	TenantID      uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Token         string     `json:"-" db:"token"`
	RefreshToken  string     `json:"-" db:"refresh_token"`
	IPAddress     string     `json:"ip_address" db:"ip_address"`
	UserAgent     string     `json:"user_agent" db:"user_agent"`
	LastActivity  time.Time  `json:"last_activity" db:"last_activity"`
	ExpiresAt     time.Time  `json:"expires_at" db:"expires_at"`
	Revoked       bool       `json:"revoked" db:"revoked"`
	RevokedAt     *time.Time `json:"revoked_at" db:"revoked_at"`
	RevokedReason *string    `json:"revoked_reason" db:"revoked_reason"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// OIDCClient represents an OIDC client application
type OIDCClient struct {
	ID                      uuid.UUID  `json:"id" db:"id"`
	TenantID                uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ClientID                string     `json:"client_id" db:"client_id"`
	ClientSecret            string     `json:"-" db:"client_secret"`
	Name                    string     `json:"name" db:"name"`
	Description             *string    `json:"description" db:"description"`
	LogoURL                 *string    `json:"logo_url" db:"logo_url"`
	RedirectURIs            []string   `json:"redirect_uris" db:"redirect_uris"`
	AllowedScopes           []string   `json:"allowed_scopes" db:"allowed_scopes"`
	GrantTypes              []string   `json:"grant_types" db:"grant_types"`
	ResponseTypes           []string   `json:"response_types" db:"response_types"`
	TokenEndpointAuthMethod string     `json:"token_endpoint_auth_method" db:"token_endpoint_auth_method"`
	AccessTokenTTL          int        `json:"access_token_ttl" db:"access_token_ttl"`
	RefreshTokenTTL         int        `json:"refresh_token_ttl" db:"refresh_token_ttl"`
	IDTokenTTL              int        `json:"id_token_ttl" db:"id_token_ttl"`
	RequireConsent          bool       `json:"require_consent" db:"require_consent"`
	RequirePKCE             bool       `json:"require_pkce" db:"require_pkce"`
	IsPublic                bool       `json:"is_public" db:"is_public"`
	IsActive                bool       `json:"is_active" db:"is_active"`
	Metadata                JSONMap    `json:"metadata" db:"metadata"`
	CreatedAt               time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt               *time.Time `json:"deleted_at" db:"deleted_at"`
}

// AuthorizationCode represents an OAuth2/OIDC authorization code
type AuthorizationCode struct {
	ID                  uuid.UUID  `json:"id" db:"id"`
	Code                string     `json:"-" db:"code"`
	ClientID            string     `json:"client_id" db:"client_id"`
	UserID              uuid.UUID  `json:"user_id" db:"user_id"`
	TenantID            uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	RedirectURI         string     `json:"redirect_uri" db:"redirect_uri"`
	Scope               string     `json:"scope" db:"scope"`
	State               *string    `json:"state" db:"state"`
	Nonce               *string    `json:"nonce" db:"nonce"`
	CodeChallenge       *string    `json:"code_challenge" db:"code_challenge"`
	CodeChallengeMethod *string    `json:"code_challenge_method" db:"code_challenge_method"`
	Used                bool       `json:"used" db:"used"`
	UsedAt              *time.Time `json:"used_at" db:"used_at"`
	ExpiresAt           time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
}

// RefreshToken represents an OAuth2/OIDC refresh token
type RefreshToken struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	Token     string     `json:"-" db:"token"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	TenantID  uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ClientID  string     `json:"client_id" db:"client_id"`
	Scope     string     `json:"scope" db:"scope"`
	Revoked   bool       `json:"revoked" db:"revoked"`
	RevokedAt *time.Time `json:"revoked_at" db:"revoked_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	TenantID   uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	UserID     *uuid.UUID `json:"user_id" db:"user_id"`
	Action     string     `json:"action" db:"action"`
	Resource   string     `json:"resource" db:"resource"`
	ResourceID *string    `json:"resource_id" db:"resource_id"`
	Details    JSONMap    `json:"details" db:"details"`
	IPAddress  string     `json:"ip_address" db:"ip_address"`
	UserAgent  string     `json:"user_agent" db:"user_agent"`
	Success    bool       `json:"success" db:"success"`
	ErrorMsg   *string    `json:"error_message" db:"error_message"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// JSONMap represents a JSON object stored in the database
type JSONMap map[string]interface{}

// Permission constants for RBAC
const (
	// User permissions
	PermissionUserRead   = "user:read"
	PermissionUserWrite  = "user:write"
	PermissionUserDelete = "user:delete"
	PermissionUserAdmin  = "user:admin"

	// Tenant permissions
	PermissionTenantRead   = "tenant:read"
	PermissionTenantWrite  = "tenant:write"
	PermissionTenantDelete = "tenant:delete"
	PermissionTenantAdmin  = "tenant:admin"

	// Role permissions
	PermissionRoleRead   = "role:read"
	PermissionRoleWrite  = "role:write"
	PermissionRoleDelete = "role:delete"
	PermissionRoleAdmin  = "role:admin"

	// OIDC permissions
	PermissionOIDCRead   = "oidc:read"
	PermissionOIDCWrite  = "oidc:write"
	PermissionOIDCDelete = "oidc:delete"
	PermissionOIDCAdmin  = "oidc:admin"

	// Audit permissions
	PermissionAuditRead = "audit:read"

	// System permissions
	PermissionSystemAdmin = "system:admin"
)

// System role constants
const (
	RoleSystemAdmin = "system_admin"
	RoleTenantAdmin = "tenant_admin"
	RoleUser        = "user"
)

// OIDC scope constants
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopePhone   = "phone"
	ScopeAddress = "address"
	ScopeOffline = "offline_access"
)

// Grant type constants
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
)

// Response type constants
const (
	ResponseTypeCode = "code"
)

// Token endpoint auth method constants
const (
	TokenEndpointAuthClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthClientSecretPost  = "client_secret_post"
	TokenEndpointAuthNone              = "none"
)
