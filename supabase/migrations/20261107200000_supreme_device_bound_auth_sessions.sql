-- Supreme device-bound application sessions and Supabase Auth access-token hook.
-- The hook adds a signed claim only when the current Auth session is bound to
-- an active, attested Android device and the sole Supreme ruler identity.
-- No Neweix Account or workforce profile is consulted.

create table if not exists supreme.devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete restrict,
  device_key_sha256 text not null
    check (device_key_sha256 ~ '^[a-f0-9]{64}$'),
  app_package text not null
    check (app_package = 'com.neweix.supreme'),
  signing_certificate_sha256 text not null
    check (signing_certificate_sha256 ~ '^[a-f0-9]{64}$'),
  security_level text not null
    check (security_level in ('software', 'trusted_environment', 'strongbox')),
  attested_at timestamptz not null,
  last_seen_at timestamptz,
  status text not null default 'active'
    check (status in ('active', 'revoked', 'blocked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, device_key_sha256)
);

create table if not exists supreme.app_sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete restrict,
  device_id uuid not null references supreme.devices(id) on delete restrict,
  auth_session_id uuid not null unique,
  status text not null default 'active'
    check (status in ('active', 'revoked', 'expired')),
  attested_at timestamptz not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (expires_at > created_at),
  check ((status = 'revoked') = (revoked_at is not null))
);

create index if not exists supreme_devices_user_status_idx
  on supreme.devices (user_id, status, created_at desc);
create index if not exists supreme_app_sessions_user_status_idx
  on supreme.app_sessions (user_id, status, expires_at desc);
create index if not exists supreme_app_sessions_device_idx
  on supreme.app_sessions (device_id, status, expires_at desc);

alter table supreme.devices enable row level security;
alter table supreme.app_sessions enable row level security;
revoke all on table supreme.devices, supreme.app_sessions
  from public, anon, authenticated;
grant select, insert, update, delete on table supreme.devices, supreme.app_sessions
  to service_role;

-- Supabase Auth invokes this function as supabase_auth_admin. It must be
-- SECURITY DEFINER because the session/device tables are not exposed to clients.
-- The function is deliberately read-only and emits only a small signed claim.
create or replace function public.supreme_custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  claims jsonb;
  event_user_id uuid;
  event_session_id uuid;
  session_row record;
begin
  claims := coalesce(event -> 'claims', '{}'::jsonb);

  if coalesce(event ->> 'user_id', '') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    claims := claims - 'supreme_app_session';
    return jsonb_set(event, '{claims}', claims, true);
  end if;
  event_user_id := (event ->> 'user_id')::uuid;

  if coalesce(claims ->> 'session_id', '') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    claims := claims - 'supreme_app_session';
    return jsonb_set(event, '{claims}', claims, true);
  end if;
  event_session_id := (claims ->> 'session_id')::uuid;

  -- Non-Supreme Auth users are not modified by this hook.
  if not exists (
    select 1
    from supreme.identities i
    where i.user_id = event_user_id
      and i.public_id = 'supreme'
      and i.role = 'ruler'
      and i.is_active = true
  ) then
    claims := claims - 'supreme_app_session';
    return jsonb_set(event, '{claims}', claims, true);
  end if;

  select
    s.id as session_id,
    s.device_id,
    extract(epoch from d.attested_at)::bigint as attested_at
  into session_row
  from supreme.app_sessions s
  join supreme.devices d on d.id = s.device_id
  where s.user_id = event_user_id
    and s.auth_session_id = event_session_id
    and s.status = 'active'
    and s.expires_at > now() and s.expires_at <= s.created_at + interval '4 hours'
    and d.user_id = event_user_id
    and d.status = 'active'
    and d.app_package = 'com.neweix.supreme'
    and d.attested_at <= now()
    and d.attested_at > now() - interval '30 days'
  limit 1;

  if session_row.session_id is null then
    claims := claims - 'supreme_app_session';
  else
    claims := jsonb_set(
      claims,
      '{supreme_app_session}',
      jsonb_build_object(
        'status', 'active',
        'session_id', session_row.session_id,
        'device_id', session_row.device_id,
        'attested_at', session_row.attested_at
      ),
      true
    );
  end if;

  return jsonb_set(event, '{claims}', claims, true);
end;
$$;

revoke all on function public.supreme_custom_access_token_hook(jsonb)
  from public, anon, authenticated;
grant usage on schema supreme to supabase_auth_admin;
grant select on supreme.identities, supreme.devices, supreme.app_sessions
  to supabase_auth_admin;
grant execute on function public.supreme_custom_access_token_hook(jsonb)
  to supabase_auth_admin;

comment on function public.supreme_custom_access_token_hook(jsonb) is
  'Supabase Custom Access Token Hook. Adds supreme_app_session only for the active Supreme ruler identity with an active attested Android device session. Enable as the Custom Access Token Hook in Supabase Auth Hooks settings.';
