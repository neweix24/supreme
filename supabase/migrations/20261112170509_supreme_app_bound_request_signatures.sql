-- Supreme app-bound API request-signature prerequisites.
-- Applied to the Supreme production Supabase project as migration version 20261112170509.
-- The production schema was verified after application; the matching Android/API rollout remains separate.

alter table supreme.devices
  add column if not exists device_request_signing_key_sha256 text,
  add column if not exists device_request_signing_public_key_spki bytea;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'supreme_devices_request_signing_key_sha256_check'
      and conrelid = 'supreme.devices'::regclass
  ) then
    alter table supreme.devices
      add constraint supreme_devices_request_signing_key_sha256_check
      check (
        device_request_signing_key_sha256 is null
        or device_request_signing_key_sha256 ~ '^[a-f0-9]{64}$'
      );
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'supreme_devices_request_signing_spki_check'
      and conrelid = 'supreme.devices'::regclass
  ) then
    alter table supreme.devices
      add constraint supreme_devices_request_signing_spki_check
      check (
        device_request_signing_public_key_spki is null
        or octet_length(device_request_signing_public_key_spki) between 64 and 256
      );
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'supreme_devices_request_signing_pair_check'
      and conrelid = 'supreme.devices'::regclass
  ) then
    alter table supreme.devices
      add constraint supreme_devices_request_signing_pair_check
      check (
        (device_request_signing_key_sha256 is null)
        = (device_request_signing_public_key_spki is null)
      );
  end if;
end
$$;

create table if not exists supreme.api_request_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  app_session_id uuid not null references supreme.app_sessions(id) on delete cascade,
  device_id uuid not null references supreme.devices(id) on delete cascade,
  nonce_sha256 bytea not null unique
    check (octet_length(nonce_sha256) = 32),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at)
);

create index if not exists supreme_api_request_challenges_device_created_idx
  on supreme.api_request_challenges (device_id, created_at desc);

create index if not exists supreme_api_request_challenges_expiry_idx
  on supreme.api_request_challenges (expires_at)
  where consumed_at is null;

alter table supreme.api_request_challenges enable row level security;
revoke all on supreme.api_request_challenges from public, anon, authenticated;
grant select, insert, update, delete on supreme.api_request_challenges to service_role;

comment on column supreme.devices.device_request_signing_key_sha256 is
  'SHA-256 fingerprint of the separately attested P-256 Android Keystore API request-signing public key. Not the biometric approval key.';
comment on column supreme.devices.device_request_signing_public_key_spki is
  'SPKI DER public key extracted from a Google-verified Android hardware attestation chain for request signing. Private key never leaves Android Keystore.';
comment on table supreme.api_request_challenges is
  'Short-lived, one-time API request nonces bound to the exact Supreme user, app session and attested device. Only nonce SHA-256 is stored; clients return the nonce for hash comparison.';
