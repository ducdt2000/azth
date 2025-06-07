package constants

// Permission constants for RBAC system
// These constants define all permission strings used throughout the application
// Format: [MODULE]_[RESOURCE]_[ACTION] = "module:action" or "[module]:[specific_action]"

// User permissions
const (
	// Basic user operations
	PermUserCreate         = "user:create"
	PermUserRead           = "user:read"
	PermUserUpdate         = "user:update"
	PermUserDelete         = "user:delete"
	PermUserStats          = "user:stats"
	PermUserBulkUpdate     = "user:bulk_update"
	PermUserUpdatePassword = "user:update_password"
	PermUserAssignRole     = "user:assign_role"
	PermUserRevokeRole     = "user:revoke_role"
)

// Tenant permissions
const (
	// Basic tenant operations
	PermTenantCreate     = "tenant:create"
	PermTenantRead       = "tenant:read"
	PermTenantUpdate     = "tenant:update"
	PermTenantDelete     = "tenant:delete"
	PermTenantActivate   = "tenant:activate"
	PermTenantDeactivate = "tenant:deactivate"
	PermTenantSuspend    = "tenant:suspend"
)

// Role permissions
const (
	// Basic role operations
	PermRoleCreate     = "role:create"
	PermRoleRead       = "role:read"
	PermRoleUpdate     = "role:update"
	PermRoleDelete     = "role:delete"
	PermRoleStats      = "role:stats"
	PermRoleBulkCreate = "role:bulk_create"
	PermRoleBulkDelete = "role:bulk_delete"
)

// Permission permissions (meta-permissions)
const (
	// Basic permission operations
	PermPermissionCreate     = "permission:create"
	PermPermissionRead       = "permission:read"
	PermPermissionUpdate     = "permission:update"
	PermPermissionDelete     = "permission:delete"
	PermPermissionAssign     = "permission:assign"
	PermPermissionRevoke     = "permission:revoke"
	PermPermissionBulkCreate = "permission:bulk_create"
	PermPermissionBulkDelete = "permission:bulk_delete"
	PermPermissionValidate   = "permission:validate"
)

// System and administrative permissions
const (
	// System-level permissions
	PermSystemAdmin = "system:admin"
	PermGlobalAdmin = "global:admin"
	PermAuditRead   = "audit:read"
)

// OIDC permissions
const (
	PermOIDCRead   = "oidc:read"
	PermOIDCWrite  = "oidc:write"
	PermOIDCDelete = "oidc:delete"
	PermOIDCAdmin  = "oidc:admin"
)

// Role constants for commonly used roles
const (
	RoleAdmin      = "admin"
	RoleModerator  = "moderator"
	RoleUser       = "user"
	RoleGuest      = "guest"
	RoleOwner      = "owner"
	RoleManager    = "manager"
	RoleDeveloper  = "developer"
	RoleSupport    = "support"
	RoleAnalyst    = "analyst"
	RoleSuperAdmin = "super_admin"
)
