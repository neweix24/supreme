-- Supreme owns its principal directory. It is intentionally separate from
-- Neweix customer accounts and any future Neweix Employees identity domain.
-- Supabase Auth remains the credential/session provider; this table is the
-- authoritative Supreme authorization identity.

create schema if not exists supreme;
revoke all on schema supreme from public, anon, authenticated;
grant usage on schema supreme to service_role;

create table if not exists supreme.identities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete restrict,
  public_id text not null default 'supreme'
    check (public_id = 'supreme'),
  role text not null default 'ruler'
    check (role = 'ruler'),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- There can be only one Supreme identity, active or inactive.
create unique index if not exists supreme_identities_single_principal_uidx
  on supreme.identities (public_id);

comment on table supreme.identities is
  'The single Supreme ruler identity. Separate from Neweix Account customers and Neweix Employees.';
comment on column supreme.identities.user_id is
  'The linked Supabase Auth user UUID; credentials remain in auth.users.';
comment on column supreme.identities.public_id is
  'Stable Supreme principal identifier; the only permitted value is supreme.';

alter table supreme.identities enable row level security;
revoke all on table supreme.identities from public, anon, authenticated;
grant select, insert, update, delete on table supreme.identities to service_role;

-- Idempotent handoff. If production has already moved Supreme into this table,
-- verify and retain that principal. Otherwise migrate the single legacy row.
do $$
declare
  identity_count integer;
  identity_user_id uuid;
  source_count integer;
  source_user_id uuid;
begin
  select count(*)::integer, (array_agg(user_id))[1]
    into identity_count, identity_user_id
  from supreme.identities
  where public_id = 'supreme'
    and role = 'ruler'
    and is_active = true;

  if identity_count = 1 and identity_user_id is not null then
    -- The principal has already been migrated; keep it unchanged.
    null;
  elsif identity_count <> 0 then
    raise exception 'SUPREME_IDENTITY_STATE_INVALID';
  else
    if to_regclass('public.staff_profiles') is null then
      raise exception 'SUPREME_IDENTITY_SOURCE_NOT_FOUND';
    end if;

    select count(*)::integer, (array_agg(user_id))[1]
      into source_count, source_user_id
    from public.staff_profiles
    where role = 'supreme'
      and public_id = 'supreme'
      and is_active = true;

    if source_count <> 1 or source_user_id is null then
      raise exception 'EXPECTED_EXACTLY_ONE_ACTIVE_SUPREME_SOURCE_IDENTITY';
    end if;

    insert into supreme.identities (user_id, public_id, role, is_active)
    values (source_user_id, 'supreme', 'ruler', true);
  end if;
end;
$$;

-- Record the initial registry bootstrap under the migrated principal.
insert into supreme.audit_events (
  actor_user_id, action, outcome, policy_version, details
)
select
  i.user_id,
  'registry.bootstrap',
  'success',
  'v1',
  jsonb_build_object(
    'services_registered', array['neweix', 'neweix-shop', 'eixon', 'neweix-account', 'neweix-message', 'supreme'],
    'capabilities_enabled', false,
    'note', 'Initial registry metadata only; no provider operation adapters are enabled.'
  )
from supreme.identities i
where i.role = 'ruler' and i.is_active = true and i.public_id = 'supreme'
on conflict do nothing;
