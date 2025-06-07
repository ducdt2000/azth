package constants

import (
	"testing"
)

func TestPermissionConstants(t *testing.T) {
	// Test that all permission constants are properly defined
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"User Create", PermUserCreate, "user:create"},
		{"User Read", PermUserRead, "user:read"},
		{"User Update", PermUserUpdate, "user:update"},
		{"User Delete", PermUserDelete, "user:delete"},
		{"Tenant Create", PermTenantCreate, "tenant:create"},
		{"Tenant Read", PermTenantRead, "tenant:read"},
		{"Role Create", PermRoleCreate, "role:create"},
		{"Role Read", PermRoleRead, "role:read"},
		{"Permission Create", PermPermissionCreate, "permission:create"},
		{"Permission Read", PermPermissionRead, "permission:read"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Expected %s to be %s, got %s", tt.name, tt.expected, tt.constant)
			}
		})
	}
}

func TestRoleConstants(t *testing.T) {
	// Test that all role constants are properly defined
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Admin Role", RoleAdmin, "admin"},
		{"User Role", RoleUser, "user"},
		{"Super Admin Role", RoleSuperAdmin, "super_admin"},
		{"Moderator Role", RoleModerator, "moderator"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Expected %s to be %s, got %s", tt.name, tt.expected, tt.constant)
			}
		})
	}
}

func TestPermissionConstantsNotEmpty(t *testing.T) {
	// Test that no permission constants are empty
	permissions := []string{
		PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete,
		PermTenantCreate, PermTenantRead, PermTenantUpdate, PermTenantDelete,
		PermRoleCreate, PermRoleRead, PermRoleUpdate, PermRoleDelete,
		PermPermissionCreate, PermPermissionRead, PermPermissionUpdate, PermPermissionDelete,
	}

	for _, perm := range permissions {
		if perm == "" {
			t.Errorf("Permission constant should not be empty")
		}
	}
}
