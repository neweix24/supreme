-- Minimal disposable PostgreSQL fixture for Supreme device and recovery migrations.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role; END IF;
END;
$$;

CREATE SCHEMA auth;
CREATE TABLE auth.users (id uuid PRIMARY KEY);
CREATE TABLE auth.sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users(id),
  not_after timestamptz NOT NULL
);

CREATE SCHEMA supreme;
CREATE TABLE supreme.identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
  public_id text NOT NULL,
  role text NOT NULL,
  is_active boolean NOT NULL DEFAULT true
);

CREATE TABLE supreme.devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
  device_key_sha256 text NOT NULL CHECK (device_key_sha256 ~ '^[a-f0-9]{64}$'),
  app_package text NOT NULL CHECK (app_package = 'com.neweix.supreme'),
  signing_certificate_sha256 text NOT NULL CHECK (signing_certificate_sha256 ~ '^[a-f0-9]{64}$'),
  security_level text NOT NULL CHECK (security_level IN ('software', 'trusted_environment', 'strongbox')),
  attested_at timestamptz NOT NULL,
  last_seen_at timestamptz,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'blocked')),
  device_public_key_spki bytea,
  device_key_biometric_auth_required boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, device_key_sha256)
);

CREATE TABLE supreme.app_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT,
  device_id uuid NOT NULL REFERENCES supreme.devices(id) ON DELETE RESTRICT,
  auth_session_id uuid NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
  attested_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE TABLE supreme.audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  action text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure', 'pending')),
  policy_version text NOT NULL DEFAULT 'v1',
  details jsonb NOT NULL DEFAULT '{}'::jsonb
);
