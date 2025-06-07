-- 010_create_otp_and_notification_tables.sql
-- Migration to create OTP, notification, MFA, and password reset tables

-- +goose Up

-- Create password_reset_tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for password_reset_tokens
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_tenant_id ON password_reset_tokens(tenant_id);
CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
CREATE INDEX idx_password_reset_tokens_used ON password_reset_tokens(used);

-- Create otp_codes table
CREATE TABLE IF NOT EXISTS otp_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('email', 'sms', 'totp')),
    purpose VARCHAR(50) NOT NULL CHECK (purpose IN ('email_verification', 'phone_verification', 'password_reset', 'mfa_verification', 'login', 'account_recovery')),
    target TEXT NOT NULL, -- email or phone number
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for otp_codes
CREATE INDEX idx_otp_codes_user_id ON otp_codes(user_id);
CREATE INDEX idx_otp_codes_tenant_id ON otp_codes(tenant_id);
CREATE INDEX idx_otp_codes_code_hash ON otp_codes(code_hash);
CREATE INDEX idx_otp_codes_type ON otp_codes(type);
CREATE INDEX idx_otp_codes_purpose ON otp_codes(purpose);
CREATE INDEX idx_otp_codes_target ON otp_codes(target);
CREATE INDEX idx_otp_codes_expires_at ON otp_codes(expires_at);
CREATE INDEX idx_otp_codes_used ON otp_codes(used);
CREATE INDEX idx_otp_codes_created_at ON otp_codes(created_at);

-- Create notification_templates table first (referenced by otp_configs)
CREATE TABLE IF NOT EXISTS notification_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE, -- NULL for global templates
    name VARCHAR(100) NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('email', 'sms')),
    purpose VARCHAR(50) NOT NULL CHECK (purpose IN ('email_verification', 'phone_verification', 'password_reset', 'mfa_verification', 'login', 'account_recovery')),
    language VARCHAR(2) NOT NULL DEFAULT 'en',
    subject TEXT, -- Required for email templates
    body TEXT NOT NULL,
    body_html TEXT, -- For email templates
    variables TEXT[] DEFAULT '{}',
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id),
    updated_by UUID REFERENCES users(id)
);

-- Create indexes for notification_templates
CREATE INDEX idx_notification_templates_tenant_id ON notification_templates(tenant_id);
CREATE INDEX idx_notification_templates_type ON notification_templates(type);
CREATE INDEX idx_notification_templates_purpose ON notification_templates(purpose);
CREATE INDEX idx_notification_templates_language ON notification_templates(language);
CREATE INDEX idx_notification_templates_is_default ON notification_templates(is_default);
CREATE INDEX idx_notification_templates_is_active ON notification_templates(is_active);

-- Create otp_configs table (after notification_templates)
CREATE TABLE IF NOT EXISTS otp_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE, -- NULL for global config
    purpose VARCHAR(50) NOT NULL CHECK (purpose IN ('email_verification', 'phone_verification', 'password_reset', 'mfa_verification', 'login', 'account_recovery')),
    type VARCHAR(20) NOT NULL CHECK (type IN ('email', 'sms', 'totp')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    code_length INTEGER NOT NULL DEFAULT 6 CHECK (code_length >= 4 AND code_length <= 10),
    expiry_minutes INTEGER NOT NULL DEFAULT 15 CHECK (expiry_minutes >= 1 AND expiry_minutes <= 60),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts >= 1 AND max_attempts <= 10),
    cooldown_minutes INTEGER NOT NULL DEFAULT 1 CHECK (cooldown_minutes >= 0 AND cooldown_minutes <= 60),
    rate_limit_per_hour INTEGER NOT NULL DEFAULT 10 CHECK (rate_limit_per_hour >= 1 AND rate_limit_per_hour <= 100),
    rate_limit_per_day INTEGER NOT NULL DEFAULT 50 CHECK (rate_limit_per_day >= 1 AND rate_limit_per_day <= 1000),
    is_numeric_only BOOLEAN NOT NULL DEFAULT TRUE,
    template_id UUID REFERENCES notification_templates(id) ON DELETE SET NULL,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id),
    updated_by UUID REFERENCES users(id)
);

-- Create unique constraint for otp_configs (tenant_id can be NULL for global configs)
CREATE UNIQUE INDEX idx_otp_configs_unique ON otp_configs(COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::UUID), purpose, type);

-- Create indexes for otp_configs
CREATE INDEX idx_otp_configs_tenant_id ON otp_configs(tenant_id);
CREATE INDEX idx_otp_configs_purpose ON otp_configs(purpose);
CREATE INDEX idx_otp_configs_type ON otp_configs(type);
CREATE INDEX idx_otp_configs_enabled ON otp_configs(enabled);

-- Create mfa_configs table
CREATE TABLE IF NOT EXISTS mfa_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE, -- NULL for global config
    sms_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    email_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    totp_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    totp_issuer VARCHAR(100) NOT NULL DEFAULT 'AZTH',
    required_for_login BOOLEAN NOT NULL DEFAULT FALSE,
    required_for_sensitive BOOLEAN NOT NULL DEFAULT TRUE,
    rule VARCHAR(20) NOT NULL DEFAULT 'optional' CHECK (rule IN ('required', 'optional', 'prompt')),
    backup_codes_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    backup_codes_count INTEGER NOT NULL DEFAULT 10 CHECK (backup_codes_count >= 5 AND backup_codes_count <= 20),
    trusted_devices_days INTEGER NOT NULL DEFAULT 30 CHECK (trusted_devices_days >= 1 AND trusted_devices_days <= 365),
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id),
    updated_by UUID REFERENCES users(id)
);

-- Create unique constraint for mfa_configs (only one config per tenant, NULL for global)
CREATE UNIQUE INDEX idx_mfa_configs_unique ON mfa_configs(COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::UUID));

-- Create indexes for mfa_configs
CREATE INDEX idx_mfa_configs_tenant_id ON mfa_configs(tenant_id);
CREATE INDEX idx_mfa_configs_rule ON mfa_configs(rule);

-- Create notification_logs table
CREATE TABLE IF NOT EXISTS notification_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('email', 'sms')),
    purpose VARCHAR(50) NOT NULL CHECK (purpose IN ('email_verification', 'phone_verification', 'password_reset', 'mfa_verification', 'login', 'account_recovery')),
    recipient TEXT NOT NULL,
    template_id UUID REFERENCES notification_templates(id) ON DELETE SET NULL,
    subject TEXT,
    body TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'delivered', 'failed', 'bounced')),
    error_message TEXT,
    external_id TEXT, -- ID from email/SMS provider
    sent_at TIMESTAMP WITH TIME ZONE,
    delivered_at TIMESTAMP WITH TIME ZONE,
    failed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for notification_logs
CREATE INDEX idx_notification_logs_tenant_id ON notification_logs(tenant_id);
CREATE INDEX idx_notification_logs_user_id ON notification_logs(user_id);
CREATE INDEX idx_notification_logs_type ON notification_logs(type);
CREATE INDEX idx_notification_logs_purpose ON notification_logs(purpose);
CREATE INDEX idx_notification_logs_status ON notification_logs(status);
CREATE INDEX idx_notification_logs_recipient ON notification_logs(recipient);
CREATE INDEX idx_notification_logs_created_at ON notification_logs(created_at);
CREATE INDEX idx_notification_logs_sent_at ON notification_logs(sent_at);

-- Create trusted_devices table
CREATE TABLE IF NOT EXISTS trusted_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL, -- Fingerprint of device
    name VARCHAR(100) NOT NULL,
    user_agent TEXT NOT NULL,
    ip_address INET NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    trust_token TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create unique constraint for trusted_devices
CREATE UNIQUE INDEX idx_trusted_devices_unique ON trusted_devices(user_id, device_id);

-- Create indexes for trusted_devices
CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_tenant_id ON trusted_devices(tenant_id);
CREATE INDEX idx_trusted_devices_device_id ON trusted_devices(device_id);
CREATE INDEX idx_trusted_devices_is_active ON trusted_devices(is_active);
CREATE INDEX idx_trusted_devices_expires_at ON trusted_devices(expires_at);
CREATE INDEX idx_trusted_devices_last_used_at ON trusted_devices(last_used_at);

-- Insert default global configurations

-- Insert default global MFA config
INSERT INTO mfa_configs (
    id, tenant_id, sms_enabled, email_enabled, totp_enabled, totp_issuer,
    required_for_login, required_for_sensitive, rule, backup_codes_enabled,
    backup_codes_count, trusted_devices_days, created_by
) VALUES (
    gen_random_uuid(), NULL, false, false, true, 'AZTH',
    false, true, 'optional', true,
    10, 30, '00000000-0000-0000-0000-000000000001'::UUID
) ON CONFLICT DO NOTHING;

-- Insert default global OTP configs
INSERT INTO otp_configs (
    id, tenant_id, purpose, type, enabled, code_length, expiry_minutes,
    max_attempts, cooldown_minutes, rate_limit_per_hour, rate_limit_per_day,
    is_numeric_only, created_by
) VALUES 
    -- Email verification
    (gen_random_uuid(), NULL, 'email_verification', 'email', true, 6, 15, 3, 1, 10, 50, true, '00000000-0000-0000-0000-000000000001'::UUID),
    -- Phone verification
    (gen_random_uuid(), NULL, 'phone_verification', 'sms', true, 6, 15, 3, 1, 5, 20, true, '00000000-0000-0000-0000-000000000001'::UUID),
    -- Password reset
    (gen_random_uuid(), NULL, 'password_reset', 'email', true, 8, 30, 3, 5, 5, 10, false, '00000000-0000-0000-0000-000000000001'::UUID),
    -- MFA verification email
    (gen_random_uuid(), NULL, 'mfa_verification', 'email', true, 6, 5, 3, 1, 20, 100, true, '00000000-0000-0000-0000-000000000001'::UUID),
    -- MFA verification SMS
    (gen_random_uuid(), NULL, 'mfa_verification', 'sms', true, 6, 5, 3, 1, 10, 50, true, '00000000-0000-0000-0000-000000000001'::UUID),
    -- Login verification
    (gen_random_uuid(), NULL, 'login', 'email', true, 6, 10, 3, 2, 10, 30, true, '00000000-0000-0000-0000-000000000001'::UUID)
ON CONFLICT DO NOTHING;

-- Insert default notification templates
INSERT INTO notification_templates (
    id, tenant_id, name, type, purpose, language, subject, body,
    variables, is_default, is_active, created_by
) VALUES 
    -- Email verification template
    (gen_random_uuid(), NULL, 'Email Verification', 'email', 'email_verification', 'en',
     'Verify your email address',
     'Hi {{.FirstName}},\n\nPlease verify your email address by entering this code: {{.Code}}\n\nThis code will expire in {{.ExpiryMinutes}} minutes.\n\nIf you did not request this verification, please ignore this email.\n\nBest regards,\nThe AZTH Team',
     ARRAY['FirstName', 'Code', 'ExpiryMinutes'], true, true, '00000000-0000-0000-0000-000000000001'::UUID),
    
    -- Phone verification template
    (gen_random_uuid(), NULL, 'Phone Verification', 'sms', 'phone_verification', 'en',
     NULL,
     'AZTH: Your verification code is {{.Code}}. This code expires in {{.ExpiryMinutes}} minutes.',
     ARRAY['Code', 'ExpiryMinutes'], true, true, '00000000-0000-0000-0000-000000000001'::UUID),
    
    -- Password reset template
    (gen_random_uuid(), NULL, 'Password Reset', 'email', 'password_reset', 'en',
     'Reset your password',
     'Hi {{.FirstName}},\n\nYou requested to reset your password. Use this code to proceed: {{.Code}}\n\nThis code will expire in {{.ExpiryMinutes}} minutes.\n\nIf you did not request this password reset, please ignore this email and consider changing your password for security.\n\nBest regards,\nThe AZTH Team',
     ARRAY['FirstName', 'Code', 'ExpiryMinutes'], true, true, '00000000-0000-0000-0000-000000000001'::UUID),
    
    -- MFA email template
    (gen_random_uuid(), NULL, 'MFA Verification Email', 'email', 'mfa_verification', 'en',
     'Your verification code',
     'Hi {{.FirstName}},\n\nYour verification code is: {{.Code}}\n\nThis code will expire in {{.ExpiryMinutes}} minutes.\n\nBest regards,\nThe AZTH Team',
     ARRAY['FirstName', 'Code', 'ExpiryMinutes'], true, true, '00000000-0000-0000-0000-000000000001'::UUID),
    
    -- MFA SMS template
    (gen_random_uuid(), NULL, 'MFA Verification SMS', 'sms', 'mfa_verification', 'en',
     NULL,
     'AZTH: Your verification code is {{.Code}}. Expires in {{.ExpiryMinutes}} min.',
     ARRAY['Code', 'ExpiryMinutes'], true, true, '00000000-0000-0000-0000-000000000001'::UUID)
ON CONFLICT DO NOTHING;

-- +goose Down

-- Drop tables in reverse order
DROP TABLE IF EXISTS trusted_devices;
DROP TABLE IF EXISTS notification_logs;
DROP TABLE IF EXISTS mfa_configs;
DROP TABLE IF EXISTS otp_configs;
DROP TABLE IF EXISTS notification_templates;
DROP TABLE IF EXISTS otp_codes;
DROP TABLE IF EXISTS password_reset_tokens; 