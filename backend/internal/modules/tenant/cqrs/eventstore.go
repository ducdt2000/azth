package cqrs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// EventStore defines the interface for storing and retrieving events
type EventStore interface {
	// SaveEvents saves a list of events for an aggregate
	SaveEvents(ctx context.Context, aggregateID uuid.UUID, events []Event, expectedVersion int64) error

	// GetEvents retrieves all events for an aggregate
	GetEvents(ctx context.Context, aggregateID uuid.UUID) ([]Event, error)

	// GetEventsFromVersion retrieves events for an aggregate from a specific version
	GetEventsFromVersion(ctx context.Context, aggregateID uuid.UUID, fromVersion int64) ([]Event, error)

	// GetEventsByType retrieves events by type within a date range
	GetEventsByType(ctx context.Context, eventType string, fromDate, toDate *time.Time) ([]Event, error)

	// GetAllEvents retrieves all events within a date range
	GetAllEvents(ctx context.Context, fromDate, toDate *time.Time, limit, offset int) ([]Event, error)

	// GetAggregateVersion retrieves the current version of an aggregate
	GetAggregateVersion(ctx context.Context, aggregateID uuid.UUID) (int64, error)

	// CreateSnapshot creates a snapshot of an aggregate state
	CreateSnapshot(ctx context.Context, snapshot *AggregateSnapshot) error

	// GetSnapshot retrieves the latest snapshot for an aggregate
	GetSnapshot(ctx context.Context, aggregateID uuid.UUID) (*AggregateSnapshot, error)
}

// StoredEvent represents an event as stored in the database
type StoredEvent struct {
	ID          uuid.UUID `db:"id"`
	AggregateID uuid.UUID `db:"aggregate_id"`
	EventType   string    `db:"event_type"`
	EventData   string    `db:"event_data"`
	Version     int64     `db:"version"`
	Timestamp   time.Time `db:"timestamp"`
	UserID      uuid.UUID `db:"user_id"`
	TenantID    uuid.UUID `db:"tenant_id"`
	CreatedAt   time.Time `db:"created_at"`
}

// AggregateSnapshot represents a snapshot of an aggregate state
type AggregateSnapshot struct {
	ID          uuid.UUID `db:"id"`
	AggregateID uuid.UUID `db:"aggregate_id"`
	Data        string    `db:"data"`
	Version     int64     `db:"version"`
	Timestamp   time.Time `db:"timestamp"`
	CreatedAt   time.Time `db:"created_at"`
}

// PostgreSQLEventStore implements EventStore using PostgreSQL
type PostgreSQLEventStore struct {
	db *sqlx.DB
}

// NewPostgreSQLEventStore creates a new PostgreSQL event store
func NewPostgreSQLEventStore(db *sqlx.DB) *PostgreSQLEventStore {
	return &PostgreSQLEventStore{
		db: db,
	}
}

// SaveEvents saves a list of events for an aggregate with optimistic concurrency control
func (es *PostgreSQLEventStore) SaveEvents(ctx context.Context, aggregateID uuid.UUID, events []Event, expectedVersion int64) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := es.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check current version for optimistic concurrency control
	var currentVersion int64
	err = tx.GetContext(ctx, &currentVersion,
		"SELECT COALESCE(MAX(version), 0) FROM events WHERE aggregate_id = $1",
		aggregateID)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if currentVersion != expectedVersion {
		return fmt.Errorf("concurrency conflict: expected version %d, got %d", expectedVersion, currentVersion)
	}

	// Insert events
	for i, event := range events {
		eventData, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}

		storedEvent := &StoredEvent{
			ID:          uuid.New(),
			AggregateID: event.GetAggregateID(),
			EventType:   event.GetEventType(),
			EventData:   string(eventData),
			Version:     expectedVersion + int64(i) + 1,
			Timestamp:   event.GetTimestamp(),
			CreatedAt:   time.Now(),
		}

		// Extract user and tenant IDs from the event if they implement the interface
		if baseEvent, ok := event.(interface{ GetUserID() uuid.UUID }); ok {
			storedEvent.UserID = baseEvent.GetUserID()
		}
		if baseEvent, ok := event.(interface{ GetTenantID() uuid.UUID }); ok {
			storedEvent.TenantID = baseEvent.GetTenantID()
		}

		_, err = tx.NamedExecContext(ctx, `
			INSERT INTO events (id, aggregate_id, event_type, event_data, version, timestamp, user_id, tenant_id, created_at)
			VALUES (:id, :aggregate_id, :event_type, :event_data, :version, :timestamp, :user_id, :tenant_id, :created_at)
		`, storedEvent)
		if err != nil {
			return fmt.Errorf("failed to insert event: %w", err)
		}
	}

	return tx.Commit()
}

// GetEvents retrieves all events for an aggregate
func (es *PostgreSQLEventStore) GetEvents(ctx context.Context, aggregateID uuid.UUID) ([]Event, error) {
	return es.GetEventsFromVersion(ctx, aggregateID, 0)
}

// GetEventsFromVersion retrieves events for an aggregate from a specific version
func (es *PostgreSQLEventStore) GetEventsFromVersion(ctx context.Context, aggregateID uuid.UUID, fromVersion int64) ([]Event, error) {
	var storedEvents []StoredEvent
	err := es.db.SelectContext(ctx, &storedEvents, `
		SELECT id, aggregate_id, event_type, event_data, version, timestamp, user_id, tenant_id, created_at
		FROM events
		WHERE aggregate_id = $1 AND version > $2
		ORDER BY version ASC
	`, aggregateID, fromVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	events := make([]Event, len(storedEvents))
	for i, storedEvent := range storedEvents {
		event, err := es.deserializeEvent(&storedEvent)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize event: %w", err)
		}
		events[i] = event
	}

	return events, nil
}

// GetEventsByType retrieves events by type within a date range
func (es *PostgreSQLEventStore) GetEventsByType(ctx context.Context, eventType string, fromDate, toDate *time.Time) ([]Event, error) {
	query := `
		SELECT id, aggregate_id, event_type, event_data, version, timestamp, user_id, tenant_id, created_at
		FROM events
		WHERE event_type = $1
	`
	args := []interface{}{eventType}

	if fromDate != nil {
		query += " AND timestamp >= $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, *fromDate)
	}

	if toDate != nil {
		query += " AND timestamp <= $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, *toDate)
	}

	query += " ORDER BY timestamp ASC"

	var storedEvents []StoredEvent
	err := es.db.SelectContext(ctx, &storedEvents, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get events by type: %w", err)
	}

	events := make([]Event, len(storedEvents))
	for i, storedEvent := range storedEvents {
		event, err := es.deserializeEvent(&storedEvent)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize event: %w", err)
		}
		events[i] = event
	}

	return events, nil
}

// GetAllEvents retrieves all events within a date range
func (es *PostgreSQLEventStore) GetAllEvents(ctx context.Context, fromDate, toDate *time.Time, limit, offset int) ([]Event, error) {
	query := `
		SELECT id, aggregate_id, event_type, event_data, version, timestamp, user_id, tenant_id, created_at
		FROM events
		WHERE 1=1
	`
	args := []interface{}{}

	if fromDate != nil {
		query += " AND timestamp >= $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, *fromDate)
	}

	if toDate != nil {
		query += " AND timestamp <= $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, *toDate)
	}

	query += " ORDER BY timestamp ASC"

	if limit > 0 {
		query += " LIMIT $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, limit)
	}

	if offset > 0 {
		query += " OFFSET $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, offset)
	}

	var storedEvents []StoredEvent
	err := es.db.SelectContext(ctx, &storedEvents, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get all events: %w", err)
	}

	events := make([]Event, len(storedEvents))
	for i, storedEvent := range storedEvents {
		event, err := es.deserializeEvent(&storedEvent)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize event: %w", err)
		}
		events[i] = event
	}

	return events, nil
}

// GetAggregateVersion retrieves the current version of an aggregate
func (es *PostgreSQLEventStore) GetAggregateVersion(ctx context.Context, aggregateID uuid.UUID) (int64, error) {
	var version int64
	err := es.db.GetContext(ctx, &version,
		"SELECT COALESCE(MAX(version), 0) FROM events WHERE aggregate_id = $1",
		aggregateID)
	if err != nil {
		return 0, fmt.Errorf("failed to get aggregate version: %w", err)
	}
	return version, nil
}

// CreateSnapshot creates a snapshot of an aggregate state
func (es *PostgreSQLEventStore) CreateSnapshot(ctx context.Context, snapshot *AggregateSnapshot) error {
	snapshot.ID = uuid.New()
	snapshot.CreatedAt = time.Now()

	_, err := es.db.NamedExecContext(ctx, `
		INSERT INTO snapshots (id, aggregate_id, data, version, timestamp, created_at)
		VALUES (:id, :aggregate_id, :data, :version, :timestamp, :created_at)
	`, snapshot)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	return nil
}

// GetSnapshot retrieves the latest snapshot for an aggregate
func (es *PostgreSQLEventStore) GetSnapshot(ctx context.Context, aggregateID uuid.UUID) (*AggregateSnapshot, error) {
	var snapshot AggregateSnapshot
	err := es.db.GetContext(ctx, &snapshot, `
		SELECT id, aggregate_id, data, version, timestamp, created_at
		FROM snapshots
		WHERE aggregate_id = $1
		ORDER BY version DESC
		LIMIT 1
	`, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot: %w", err)
	}

	return &snapshot, nil
}

// deserializeEvent deserializes a stored event back to its concrete type
func (es *PostgreSQLEventStore) deserializeEvent(storedEvent *StoredEvent) (Event, error) {
	var event Event

	switch storedEvent.EventType {
	case TenantCreatedEventType:
		event = &TenantCreatedEvent{}
	case TenantUpdatedEventType:
		event = &TenantUpdatedEvent{}
	case TenantDeletedEventType:
		event = &TenantDeletedEvent{}
	case TenantActivatedEventType:
		event = &TenantActivatedEvent{}
	case TenantDeactivatedEventType:
		event = &TenantDeactivatedEvent{}
	case TenantSuspendedEventType:
		event = &TenantSuspendedEvent{}
	case TenantPlanChangedEventType:
		event = &TenantPlanChangedEvent{}
	case TenantSettingsUpdatedEventType:
		event = &TenantSettingsUpdatedEvent{}
	case TenantMetadataUpdatedEventType:
		event = &TenantMetadataUpdatedEvent{}
	default:
		return nil, fmt.Errorf("unknown event type: %s", storedEvent.EventType)
	}

	err := json.Unmarshal([]byte(storedEvent.EventData), event)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	return event, nil
}
