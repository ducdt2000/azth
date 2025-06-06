package cqrs

import (
	"context"
	"time"

	"github.com/ducdt2000/azth/backend/internal/modules/user/dto"
	"github.com/google/uuid"
)

// QueryType represents the type of query
type QueryType string

const (
	GetUserQueryType             QueryType = "GetUser"
	GetUserByEmailQueryType      QueryType = "GetUserByEmail"
	GetUserByUsernameQueryType   QueryType = "GetUserByUsername"
	ListUsersQueryType           QueryType = "ListUsers"
	GetUserStatsQueryType        QueryType = "GetUserStats"
	GetUserRolesQueryType        QueryType = "GetUserRoles"
	GetUserSessionsQueryType     QueryType = "GetUserSessions"
	ValidateUserQueryType        QueryType = "ValidateUser"
	CheckUserPermissionQueryType QueryType = "CheckUserPermission"
	GetUsersByRoleQueryType      QueryType = "GetUsersByRole"
	GetUsersByStatusQueryType    QueryType = "GetUsersByStatus"
	SearchUsersQueryType         QueryType = "SearchUsers"
)

// Query represents a query in the CQRS pattern
type Query interface {
	GetQueryType() QueryType
	GetTimestamp() time.Time
	GetUserID() uuid.UUID
	GetTenantID() uuid.UUID
}

// BaseQuery provides common fields for all queries
type BaseQuery struct {
	QueryType QueryType `json:"query_type"`
	Timestamp time.Time `json:"timestamp"`
	UserID    uuid.UUID `json:"user_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
}

// GetQueryType returns the query type
func (q BaseQuery) GetQueryType() QueryType {
	return q.QueryType
}

// GetTimestamp returns the timestamp
func (q BaseQuery) GetTimestamp() time.Time {
	return q.Timestamp
}

// GetUserID returns the user ID
func (q BaseQuery) GetUserID() uuid.UUID {
	return q.UserID
}

// GetTenantID returns the tenant ID
func (q BaseQuery) GetTenantID() uuid.UUID {
	return q.TenantID
}

// GetUserQuery represents a query to get a user by ID
type GetUserQuery struct {
	BaseQuery
	TargetUserID uuid.UUID `json:"target_user_id"`
}

// GetUserByEmailQuery represents a query to get a user by email
type GetUserByEmailQuery struct {
	BaseQuery
	Email string `json:"email"`
}

// GetUserByUsernameQuery represents a query to get a user by username
type GetUserByUsernameQuery struct {
	BaseQuery
	Username string `json:"username"`
}

// ListUsersQuery represents a query to list users with pagination and filtering
type ListUsersQuery struct {
	BaseQuery
	Request *dto.UserListRequest `json:"request"`
}

// GetUserStatsQuery represents a query to get user statistics
type GetUserStatsQuery struct {
	BaseQuery
	Request *dto.UserStatsRequest `json:"request"`
}

// GetUserRolesQuery represents a query to get user roles
type GetUserRolesQuery struct {
	BaseQuery
	TargetUserID uuid.UUID `json:"target_user_id"`
}

// GetUserSessionsQuery represents a query to get user sessions
type GetUserSessionsQuery struct {
	BaseQuery
	TargetUserID uuid.UUID `json:"target_user_id"`
	ActiveOnly   bool      `json:"active_only"`
}

// ValidateUserQuery represents a query to validate user credentials
type ValidateUserQuery struct {
	BaseQuery
	Email    string `json:"email"`
	Password string `json:"password"`
}

// CheckUserPermissionQuery represents a query to check user permissions
type CheckUserPermissionQuery struct {
	BaseQuery
	TargetUserID uuid.UUID `json:"target_user_id"`
	Permission   string    `json:"permission"`
	Resource     string    `json:"resource,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
}

// GetUsersByRoleQuery represents a query to get users by role
type GetUsersByRoleQuery struct {
	BaseQuery
	RoleID uuid.UUID `json:"role_id"`
	Page   int       `json:"page"`
	Limit  int       `json:"limit"`
}

// GetUsersByStatusQuery represents a query to get users by status
type GetUsersByStatusQuery struct {
	BaseQuery
	Status string `json:"status"`
	Page   int    `json:"page"`
	Limit  int    `json:"limit"`
}

// SearchUsersQuery represents a query to search users
type SearchUsersQuery struct {
	BaseQuery
	SearchTerm string   `json:"search_term"`
	Fields     []string `json:"fields,omitempty"` // email, username, first_name, last_name
	Page       int      `json:"page"`
	Limit      int      `json:"limit"`
}

// Query handler interface
type UserQueryHandler interface {
	HandleGetUser(ctx context.Context, query *GetUserQuery) (*dto.UserResponse, error)
	HandleGetUserByEmail(ctx context.Context, query *GetUserByEmailQuery) (*dto.UserResponse, error)
	HandleGetUserByUsername(ctx context.Context, query *GetUserByUsernameQuery) (*dto.UserResponse, error)
	HandleListUsers(ctx context.Context, query *ListUsersQuery) (*dto.UserListResponse, error)
	HandleGetUserStats(ctx context.Context, query *GetUserStatsQuery) (*dto.UserStatsResponse, error)
	HandleGetUserRoles(ctx context.Context, query *GetUserRolesQuery) ([]dto.UserRoleResponse, error)
	HandleGetUserSessions(ctx context.Context, query *GetUserSessionsQuery) ([]dto.SessionResponse, error)
	HandleValidateUser(ctx context.Context, query *ValidateUserQuery) (*dto.UserResponse, error)
	HandleCheckUserPermission(ctx context.Context, query *CheckUserPermissionQuery) (bool, error)
	HandleGetUsersByRole(ctx context.Context, query *GetUsersByRoleQuery) (*dto.UserListResponse, error)
	HandleGetUsersByStatus(ctx context.Context, query *GetUsersByStatusQuery) (*dto.UserListResponse, error)
	HandleSearchUsers(ctx context.Context, query *SearchUsersQuery) (*dto.UserListResponse, error)
}

// Constructor functions

// NewGetUserQuery creates a new GetUserQuery
func NewGetUserQuery(requestingUserID, tenantID, targetUserID uuid.UUID) *GetUserQuery {
	return &GetUserQuery{
		BaseQuery: BaseQuery{
			QueryType: GetUserQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		TargetUserID: targetUserID,
	}
}

// NewGetUserByEmailQuery creates a new GetUserByEmailQuery
func NewGetUserByEmailQuery(requestingUserID, tenantID uuid.UUID, email string) *GetUserByEmailQuery {
	return &GetUserByEmailQuery{
		BaseQuery: BaseQuery{
			QueryType: GetUserByEmailQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		Email: email,
	}
}

// NewGetUserByUsernameQuery creates a new GetUserByUsernameQuery
func NewGetUserByUsernameQuery(requestingUserID, tenantID uuid.UUID, username string) *GetUserByUsernameQuery {
	return &GetUserByUsernameQuery{
		BaseQuery: BaseQuery{
			QueryType: GetUserByUsernameQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		Username: username,
	}
}

// NewListUsersQuery creates a new ListUsersQuery
func NewListUsersQuery(requestingUserID, tenantID uuid.UUID, request *dto.UserListRequest) *ListUsersQuery {
	return &ListUsersQuery{
		BaseQuery: BaseQuery{
			QueryType: ListUsersQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		Request: request,
	}
}

// NewGetUserStatsQuery creates a new GetUserStatsQuery
func NewGetUserStatsQuery(requestingUserID, tenantID uuid.UUID, request *dto.UserStatsRequest) *GetUserStatsQuery {
	return &GetUserStatsQuery{
		BaseQuery: BaseQuery{
			QueryType: GetUserStatsQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		Request: request,
	}
}

// NewGetUserRolesQuery creates a new GetUserRolesQuery
func NewGetUserRolesQuery(requestingUserID, tenantID, targetUserID uuid.UUID) *GetUserRolesQuery {
	return &GetUserRolesQuery{
		BaseQuery: BaseQuery{
			QueryType: GetUserRolesQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		TargetUserID: targetUserID,
	}
}

// NewGetUserSessionsQuery creates a new GetUserSessionsQuery
func NewGetUserSessionsQuery(requestingUserID, tenantID, targetUserID uuid.UUID, activeOnly bool) *GetUserSessionsQuery {
	return &GetUserSessionsQuery{
		BaseQuery: BaseQuery{
			QueryType: GetUserSessionsQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		TargetUserID: targetUserID,
		ActiveOnly:   activeOnly,
	}
}

// NewValidateUserQuery creates a new ValidateUserQuery
func NewValidateUserQuery(tenantID uuid.UUID, email, password string) *ValidateUserQuery {
	return &ValidateUserQuery{
		BaseQuery: BaseQuery{
			QueryType: ValidateUserQueryType,
			Timestamp: time.Now(),
			UserID:    uuid.Nil, // No user yet during validation
			TenantID:  tenantID,
		},
		Email:    email,
		Password: password,
	}
}

// NewCheckUserPermissionQuery creates a new CheckUserPermissionQuery
func NewCheckUserPermissionQuery(requestingUserID, tenantID, targetUserID uuid.UUID, permission, resource, resourceID string) *CheckUserPermissionQuery {
	return &CheckUserPermissionQuery{
		BaseQuery: BaseQuery{
			QueryType: CheckUserPermissionQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		TargetUserID: targetUserID,
		Permission:   permission,
		Resource:     resource,
		ResourceID:   resourceID,
	}
}

// NewGetUsersByRoleQuery creates a new GetUsersByRoleQuery
func NewGetUsersByRoleQuery(requestingUserID, tenantID, roleID uuid.UUID, page, limit int) *GetUsersByRoleQuery {
	return &GetUsersByRoleQuery{
		BaseQuery: BaseQuery{
			QueryType: GetUsersByRoleQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		RoleID: roleID,
		Page:   page,
		Limit:  limit,
	}
}

// NewGetUsersByStatusQuery creates a new GetUsersByStatusQuery
func NewGetUsersByStatusQuery(requestingUserID, tenantID uuid.UUID, status string, page, limit int) *GetUsersByStatusQuery {
	return &GetUsersByStatusQuery{
		BaseQuery: BaseQuery{
			QueryType: GetUsersByStatusQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		Status: status,
		Page:   page,
		Limit:  limit,
	}
}

// NewSearchUsersQuery creates a new SearchUsersQuery
func NewSearchUsersQuery(requestingUserID, tenantID uuid.UUID, searchTerm string, fields []string, page, limit int) *SearchUsersQuery {
	return &SearchUsersQuery{
		BaseQuery: BaseQuery{
			QueryType: SearchUsersQueryType,
			Timestamp: time.Now(),
			UserID:    requestingUserID,
			TenantID:  tenantID,
		},
		SearchTerm: searchTerm,
		Fields:     fields,
		Page:       page,
		Limit:      limit,
	}
}
