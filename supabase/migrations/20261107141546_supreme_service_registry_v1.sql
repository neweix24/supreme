-- Supreme registry v1: isolated from Neweix commerce and Eixon financial data.
-- This schema is intentionally not exposed through the Supabase Data API.

create schema if not exists supreme;
revoke all on schema supreme from public, anon, authenticated;
grant usage on schema supreme to service_role;

create table if not exists supreme.services (
  service_id text primary key
    check (service_id ~ '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$' and char_length(service_id) <= 64),
  display_name text not null check (char_length(display_name) between 1 and 120),
  description text not null default '' check (char_length(description) <= 1000),
  repository_provider text not null
    check (repository_provider in ('github', 'gitlab', 'bitbucket', 'other')),
  repository_full_name text not null check (char_length(repository_full_name) between 3 and 200),
  repository_default_branch text not null check (char_length(repository_default_branch) between 1 and 100),
  repository_url text check (repository_url is null or repository_url ~ '^https://'),
  owner_team text not null check (char_length(owner_team) between 1 and 100),
  owner_contact_ref text check (owner_contact_ref is null or char_length(owner_contact_ref) <= 160),
  data_classification text not null default 'internal'
    check (data_classification in ('public', 'internal', 'confidential', 'restricted')),
  risk_tier text not null default 'moderate'
    check (risk_tier in ('low', 'moderate', 'high', 'critical')),
  health_check_kind text not null default 'none'
    check (health_check_kind in ('http', 'none')),
  health_check_path text,
  health_check_timeout_seconds integer not null default 5
    check (health_check_timeout_seconds between 1 and 30),
  health_check_expected_status integer[] not null default array[200],
  status text not null default 'planned'
    check (status in ('planned', 'active', 'suspended', 'retired')),
  metadata_version integer not null default 1 check (metadata_version >= 1),
  created_by uuid references auth.users(id) on delete set null,
  updated_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    (health_check_kind = 'none' and health_check_path is null)
    or
    (health_check_kind = 'http' and health_check_path is not null and health_check_path like '/%')
  ),
  check (
    cardinality(health_check_expected_status) > 0
    and health_check_expected_status <@ array[
      100,101,102,103,200,201,202,203,204,205,206,207,208,226,
      300,301,302,303,304,305,307,308,
      400,401,402,403,404,405,406,407,408,409,410,411,412,413,
      414,415,416,417,418,421,422,423,424,425,426,428,429,431,451,
      500,501,502,503,504,505,506,507,508,510,511
    ]::integer[]
  )
);

create table if not exists supreme.service_environments (
  service_id text not null references supreme.services(service_id) on delete restrict,
  environment_id text not null
    check (environment_id ~ '^[a-z][a-z0-9-]{1,31}$'),
  classification text not null
    check (classification in ('development', 'staging', 'production')),
  api_base_url text check (api_base_url is null or api_base_url ~ '^https://'),
  contract_version text check (contract_version is null or char_length(contract_version) <= 40),
  health_url text check (health_url is null or health_url ~ '^https://'),
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (service_id, environment_id),
  check (
    health_url is null
    or (
      api_base_url is not null
      and split_part(health_url, '/', 3) = split_part(api_base_url, '/', 3)
    )
  )
);

create table if not exists supreme.service_capabilities (
  service_id text not null references supreme.services(service_id) on delete restrict,
  capability text not null
    check (
      char_length(capability) <= 100
      and capability ~ '^[a-z][a-z0-9-]*(?:\\.[a-z][a-z0-9-]*)+$'
      and capability not in ('*', 'admin', 'write.all')
    ),
  created_at timestamptz not null default now(),
  primary key (service_id, capability)
);

create table if not exists supreme.service_secret_refs (
  service_id text not null references supreme.services(service_id) on delete restrict,
  secret_ref text not null
    check (secret_ref ~ '^[a-zA-Z0-9][a-zA-Z0-9/_:.-]{2,180}$'),
  created_at timestamptz not null default now(),
  primary key (service_id, secret_ref)
);
comment on table supreme.service_secret_refs is
  'Opaque secret-manager references only. Never store credential values in Supreme registry.';

create table if not exists supreme.control_requests (
  id uuid primary key default gen_random_uuid(),
  request_type text not null
    check (request_type in ('register_service', 'update_service', 'suspend_service', 'retire_service', 'execute_operation')),
  service_id text,
  environment_id text,
  action text not null check (char_length(action) between 1 and 120),
  normalized_parameters jsonb not null default '{}'::jsonb
    check (jsonb_typeof(normalized_parameters) = 'object'),
  requester_user_id uuid not null references auth.users(id) on delete restrict,
  idempotency_key text not null check (char_length(idempotency_key) between 8 and 128),
  policy_version text not null default 'v1',
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'cancelled', 'expired', 'executed', 'failed')),
  approval_required boolean not null default true,
  approved_by uuid references auth.users(id) on delete set null,
  approved_at timestamptz,
  expires_at timestamptz not null default (now() + interval '30 minutes'),
  result_summary jsonb check (result_summary is null or jsonb_typeof(result_summary) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (requester_user_id, idempotency_key),
  check ((approved_by is null) = (approved_at is null)),
  check (status <> 'approved' or approved_by is not null)
);
create index if not exists supreme_control_requests_pending_idx
  on supreme.control_requests (created_at desc)
  where status = 'pending';
create index if not exists supreme_control_requests_service_idx
  on supreme.control_requests (service_id, created_at desc);

create table if not exists supreme.audit_events (
  id bigint generated always as identity primary key,
  request_id uuid,
  actor_user_id uuid references auth.users(id) on delete set null,
  action text not null check (char_length(action) between 1 and 120),
  target_service_id text,
  environment_id text,
  outcome text not null check (outcome in ('success', 'denied', 'failure', 'pending')),
  policy_version text not null default 'v1',
  details jsonb not null default '{}'::jsonb
    check (jsonb_typeof(details) = 'object'),
  created_at timestamptz not null default now()
);
create index if not exists supreme_audit_events_created_idx
  on supreme.audit_events (created_at desc);
create index if not exists supreme_audit_events_service_idx
  on supreme.audit_events (target_service_id, created_at desc);

create or replace function supreme.reject_audit_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'Supreme audit events are append-only';
end;
$$;
revoke all on function supreme.reject_audit_mutation() from public, anon, authenticated;
drop trigger if exists supreme_audit_events_immutable on supreme.audit_events;
create trigger supreme_audit_events_immutable
before update or delete on supreme.audit_events
for each row execute function supreme.reject_audit_mutation();

alter table supreme.services enable row level security;
alter table supreme.service_environments enable row level security;
alter table supreme.service_capabilities enable row level security;
alter table supreme.service_secret_refs enable row level security;
alter table supreme.control_requests enable row level security;
alter table supreme.audit_events enable row level security;

revoke all on all tables in schema supreme from public, anon, authenticated;
grant select, insert, update, delete on all tables in schema supreme to service_role;
grant usage, select on all sequences in schema supreme to service_role;
alter default privileges in schema supreme revoke all on tables from public, anon, authenticated;
alter default privileges in schema supreme grant select, insert, update, delete on tables to service_role;
alter default privileges in schema supreme revoke all on sequences from public, anon, authenticated;
alter default privileges in schema supreme grant usage, select on sequences to service_role;
