-- Repair migration (idempotent). The production project was found WITHOUT
-- supreme.control_decision_challenges, so Approve/Reject challenges failed.
-- Safe to run on a project that already has the table.
create table if not exists supreme.control_decision_challenges (
  id uuid primary key default gen_random_uuid(),
  control_request_id uuid not null references supreme.control_requests(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete restrict,
  device_id uuid not null references supreme.devices(id) on delete cascade,
  decision text not null check (decision in ('approve', 'reject')),
  reason_sha256 bytea not null check (octet_length(reason_sha256) = 32),
  nonce_sha256 bytea not null unique check (octet_length(nonce_sha256) = 32),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at)
);

create index if not exists supreme_control_decision_challenges_expiry_idx
  on supreme.control_decision_challenges (expires_at)
  where consumed_at is null;

create index if not exists supreme_control_decision_challenges_device_created_idx
  on supreme.control_decision_challenges (user_id, device_id, created_at desc);

alter table supreme.control_decision_challenges enable row level security;
revoke all on supreme.control_decision_challenges from public, anon, authenticated;
grant select, insert, update, delete on supreme.control_decision_challenges to service_role;

alter table supreme.devices
  add column if not exists device_public_key_spki bytea,
  add column if not exists device_key_biometric_auth_required boolean not null default false;

comment on table supreme.control_decision_challenges is
  'Short-lived, single-use nonces bound to one Supreme control request, decision, reason digest, user and attested device. Raw nonce and signatures are never stored.';
