package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/ducdt2000/azth/backend/internal/domain"
)

// SessionRepository defines the interface for session data access
type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) error
	GetByToken(ctx context.Context, token string) (*domain.Session, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)
	Update(ctx context.Context, session *domain.Session) error
	RevokeByID(ctx context.Context, sessionID uuid.UUID, reason string) error
	RevokeByUserID(ctx context.Context, userID uuid.UUID, reason string) error
	DeleteExpired(ctx context.Context) error
	UpdateLastActivity(ctx context.Context, sessionID uuid.UUID, lastActivity time.Time) error
}

// sessionRepository implements SessionRepository interface
type sessionRepository struct {
	db     *sqlx.DB
	tracer trace.Tracer
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(db *sqlx.DB) SessionRepository {
	return &sessionRepository{
		db:     db,
		tracer: otel.Tracer("session-repository"),
	}
}

// Create creates a new session in the database
func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	ctx, span := r.tracer.Start(ctx, "session.repository.Create")
	defer span.End()

	query := `
		INSERT INTO sessions (
			id, user_id, tenant_id, token, refresh_token, ip_address, user_agent,
			last_activity, expires_at, revoked, created_at, updated_at
		) VALUES (
			:id, :user_id, :tenant_id, :token, :refresh_token, :ip_address, :user_agent,
			:last_activity, :expires_at, :revoked, :created_at, :updated_at
		)`

	_, err := r.db.NamedExecContext(ctx, query, session)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create session: %w", err)
	}

	span.AddEvent("session created successfully")
	return nil
}

// GetByToken retrieves a session by token
func (r *sessionRepository) GetByToken(ctx context.Context, token string) (*domain.Session, error) {
	ctx, span := r.tracer.Start(ctx, "session.repository.GetByToken")
	defer span.End()

	var session domain.Session
	query := `
		SELECT id, user_id, tenant_id, token, refresh_token, ip_address, user_agent,
		       last_activity, expires_at, revoked, revoked_at, revoked_reason,
		       created_at, updated_at
		FROM sessions
		WHERE token = $1 OR refresh_token = $1`

	err := r.db.GetContext(ctx, &session, query, token)
	if err != nil {
		if err == sql.ErrNoRows {
			span.AddEvent("session not found")
			return nil, fmt.Errorf("session not found")
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get session by token: %w", err)
	}

	span.AddEvent("session retrieved successfully")
	return &session, nil
}

// GetByID retrieves a session by ID
func (r *sessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	ctx, span := r.tracer.Start(ctx, "session.repository.GetByID")
	defer span.End()

	var session domain.Session
	query := `
		SELECT id, user_id, tenant_id, token, refresh_token, ip_address, user_agent,
		       last_activity, expires_at, revoked, revoked_at, revoked_reason,
		       created_at, updated_at
		FROM sessions
		WHERE id = $1`

	err := r.db.GetContext(ctx, &session, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			span.AddEvent("session not found")
			return nil, fmt.Errorf("session not found")
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get session by ID: %w", err)
	}

	span.AddEvent("session retrieved successfully")
	return &session, nil
}

// GetByUserID retrieves all sessions for a user
func (r *sessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	ctx, span := r.tracer.Start(ctx, "session.repository.GetByUserID")
	defer span.End()

	var sessions []*domain.Session
	query := `
		SELECT id, user_id, tenant_id, token, refresh_token, ip_address, user_agent,
		       last_activity, expires_at, revoked, revoked_at, revoked_reason,
		       created_at, updated_at
		FROM sessions
		WHERE user_id = $1
		ORDER BY last_activity DESC`

	err := r.db.SelectContext(ctx, &sessions, query, userID)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get sessions by user ID: %w", err)
	}

	span.AddEvent("sessions retrieved successfully", trace.WithAttributes())
	return sessions, nil
}

// Update updates an existing session
func (r *sessionRepository) Update(ctx context.Context, session *domain.Session) error {
	ctx, span := r.tracer.Start(ctx, "session.repository.Update")
	defer span.End()

	query := `
		UPDATE sessions SET
			token = :token,
			refresh_token = :refresh_token,
			ip_address = :ip_address,
			user_agent = :user_agent,
			last_activity = :last_activity,
			expires_at = :expires_at,
			revoked = :revoked,
			revoked_at = :revoked_at,
			revoked_reason = :revoked_reason,
			updated_at = :updated_at
		WHERE id = :id`

	result, err := r.db.NamedExecContext(ctx, query, session)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to update session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		span.AddEvent("session not found for update")
		return fmt.Errorf("session not found")
	}

	span.AddEvent("session updated successfully")
	return nil
}

// RevokeByID revokes a session by ID
func (r *sessionRepository) RevokeByID(ctx context.Context, sessionID uuid.UUID, reason string) error {
	ctx, span := r.tracer.Start(ctx, "session.repository.RevokeByID")
	defer span.End()

	now := time.Now()
	query := `
		UPDATE sessions SET
			revoked = true,
			revoked_at = $1,
			revoked_reason = $2,
			updated_at = $1
		WHERE id = $3 AND revoked = false`

	result, err := r.db.ExecContext(ctx, query, now, reason, sessionID)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		span.AddEvent("session not found or already revoked")
		return fmt.Errorf("session not found or already revoked")
	}

	span.AddEvent("session revoked successfully")
	return nil
}

// RevokeByUserID revokes all sessions for a user
func (r *sessionRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID, reason string) error {
	ctx, span := r.tracer.Start(ctx, "session.repository.RevokeByUserID")
	defer span.End()

	now := time.Now()
	query := `
		UPDATE sessions SET
			revoked = true,
			revoked_at = $1,
			revoked_reason = $2,
			updated_at = $1
		WHERE user_id = $3 AND revoked = false`

	_, err := r.db.ExecContext(ctx, query, now, reason, userID)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}

	span.AddEvent("user sessions revoked successfully")
	return nil
}

// DeleteExpired deletes expired sessions from the database
func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	ctx, span := r.tracer.Start(ctx, "session.repository.DeleteExpired")
	defer span.End()

	query := `DELETE FROM sessions WHERE expires_at < $1`

	_, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	span.AddEvent("expired sessions deleted successfully")
	return nil
}

// UpdateLastActivity updates the last activity timestamp of a session
func (r *sessionRepository) UpdateLastActivity(ctx context.Context, sessionID uuid.UUID, lastActivity time.Time) error {
	ctx, span := r.tracer.Start(ctx, "session.repository.UpdateLastActivity")
	defer span.End()

	query := `
		UPDATE sessions SET
			last_activity = $1,
			updated_at = $1
		WHERE id = $2`

	result, err := r.db.ExecContext(ctx, query, lastActivity, sessionID)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		span.AddEvent("session not found for activity update")
		return fmt.Errorf("session not found")
	}

	span.AddEvent("session activity updated successfully")
	return nil
}
