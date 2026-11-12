-- Supabase roles required by production migration grants.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role;
  end if;
end;
$$;

-- Minimal disposable PostgreSQL fixture for the Supreme audit-chain migration test.
create schema auth;
create table auth.users (
  id uuid primary key
);

create schema supreme;
create table supreme.audit_events (
  id bigint generated always as identity primary key,
  request_id uuid,
  actor_user_id uuid references auth.users(id) on delete set null,
  action text not null check (char_length(action) between 1 and 120),
  target_service_id text,
  environment_id text,
  outcome text not null check (outcome in ('success', 'denied', 'failure', 'pending')),
  policy_version text not null default 'v1',
  details jsonb not null default '{}'::jsonb check (jsonb_typeof(details) = 'object'),
  created_at timestamptz not null default now()
);

create or replace function supreme.reject_audit_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'Supreme audit events are append-only';
end;
$$;

create trigger supreme_audit_events_immutable
before update or delete on supreme.audit_events
for each row execute function supreme.reject_audit_mutation();

-- Seed legacy events before the hash-chain migration to exercise backfill.
insert into supreme.audit_events (
  request_id, actor_user_id, action, outcome, policy_version, details
) values
  (gen_random_uuid(), null, 'legacy.audit.event.one', 'success', 'v1', jsonb_build_object('legacy', 1)),
  (gen_random_uuid(), null, 'legacy.audit.event.two', 'pending', 'v1', jsonb_build_object('legacy', 2));


-- Minimal parent-table fixture for the app-bound request-signature migration.
create table supreme.devices (
  id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade
);

create table supreme.app_sessions (
  id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  device_id uuid not null references supreme.devices(id) on delete cascade
);
