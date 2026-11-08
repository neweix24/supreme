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
