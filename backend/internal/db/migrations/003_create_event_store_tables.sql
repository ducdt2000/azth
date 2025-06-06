-- Migration: Create Event Store Tables
-- Description: Creates tables for event sourcing implementation

-- Events table to store all domain events
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(255) NOT NULL,
    event_data JSONB NOT NULL,
    version BIGINT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id UUID,
    tenant_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Unique constraint to ensure event ordering per aggregate
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_aggregate_version 
ON events(aggregate_id, version);

-- Index for querying events by type
CREATE INDEX IF NOT EXISTS idx_events_type 
ON events(event_type);

-- Index for querying events by timestamp
CREATE INDEX IF NOT EXISTS idx_events_timestamp 
ON events(timestamp);

-- Index for querying events by tenant
CREATE INDEX IF NOT EXISTS idx_events_tenant 
ON events(tenant_id) WHERE tenant_id IS NOT NULL;

-- Index for querying events by user
CREATE INDEX IF NOT EXISTS idx_events_user 
ON events(user_id) WHERE user_id IS NOT NULL;

-- Snapshots table for aggregate state snapshots
CREATE TABLE IF NOT EXISTS snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id UUID NOT NULL,
    data JSONB NOT NULL,
    version BIGINT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Unique constraint to ensure one snapshot per version
CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshots_aggregate_version 
ON snapshots(aggregate_id, version);

-- Index for getting latest snapshot
CREATE INDEX IF NOT EXISTS idx_snapshots_aggregate_latest 
ON snapshots(aggregate_id, version DESC);

-- Add comments for documentation
COMMENT ON TABLE events IS 'Stores domain events for event sourcing';
COMMENT ON COLUMN events.aggregate_id IS 'ID of the aggregate that generated the event';
COMMENT ON COLUMN events.event_type IS 'Type of the event (e.g., tenant.created)';
COMMENT ON COLUMN events.event_data IS 'JSON serialized event data';
COMMENT ON COLUMN events.version IS 'Version number for optimistic concurrency control';
COMMENT ON COLUMN events.timestamp IS 'When the event occurred';
COMMENT ON COLUMN events.user_id IS 'User who triggered the event';
COMMENT ON COLUMN events.tenant_id IS 'Tenant context for the event';

COMMENT ON TABLE snapshots IS 'Stores aggregate state snapshots for performance optimization';
COMMENT ON COLUMN snapshots.aggregate_id IS 'ID of the aggregate';
COMMENT ON COLUMN snapshots.data IS 'JSON serialized aggregate state';
COMMENT ON COLUMN snapshots.version IS 'Version of the aggregate at snapshot time';
COMMENT ON COLUMN snapshots.timestamp IS 'When the snapshot was created'; 