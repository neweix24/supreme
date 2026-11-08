-- Supreme break-glass recovery.
-- Offline 256-bit recovery material; 24-hour cooling-off; one pending request;
-- recovery is atomic, single-use, audited, and invalidates every previous session.
-- The Edge Function must deliver independent notifications before completion.

create table if not exists supreme.recovery_authorizations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete restrict,
  token_sha256 text not null unique check (token_sha256 ~ '^[a-f0-9]{64}$'),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  consumed_by_request_id uuid,
  check (expires_at > created_at),
  check ((consumed_at is null) = (consumed_by_request_id is null))
);

create table if not exists supreme.recovery_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete restrict,
  authorization_id uuid not null references supreme.recovery_authorizations(id) on delete restrict,
  requester_auth_session_id uuid not null,
  status text not null default 'pending'
    check (status in ('pending', 'completed', 'cancelled', 'expired')),
  requested_at timestamptz not null default now(),
  available_at timestamptz not null default (now() + interval '24 hours'),
  expires_at timestamptz not null default (now() + interval '7 days'),
  notification_sent_at timestamptz,
  completed_at timestamptz,
  completed_device_id uuid references supreme.devices(id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (available_at > requested_at),
  check (expires_at > available_at),
  check ((status = 'completed') = (completed_at is not null)),
  check ((status = 'completed') = (completed_device_id is not null))
);

create unique index if not exists supreme_one_pending_recovery_per_user
  on supreme.recovery_requests(user_id) where status = 'pending';
create index if not exists supreme_recovery_requests_due_idx
  on supreme.recovery_requests(user_id, available_at) where status = 'pending';

create table if not exists supreme.recovery_notification_outbox (
  id uuid primary key default gen_random_uuid(),
  recovery_request_id uuid not null references supreme.recovery_requests(id) on delete restrict,
  event_type text not null check (event_type in ('requested', 'completed')),
  payload jsonb not null,
  created_at timestamptz not null default now(),
  delivered_at timestamptz,
  attempts integer not null default 0 check (attempts >= 0),
  last_error_code text,
  unique (recovery_request_id, event_type)
);

alter table supreme.recovery_authorizations enable row level security;
alter table supreme.recovery_requests enable row level security;
alter table supreme.recovery_notification_outbox enable row level security;
revoke all on table supreme.recovery_authorizations,
  supreme.recovery_requests, supreme.recovery_notification_outbox
  from public, anon, authenticated;
grant select, insert, update, delete on table supreme.recovery_authorizations,
  supreme.recovery_requests, supreme.recovery_notification_outbox to service_role;

create or replace function public.begin_supreme_break_glass_recovery(
  p_user_id uuid,
  p_auth_session_id uuid,
  p_token_sha256 text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_authorization supreme.recovery_authorizations%rowtype;
  v_request supreme.recovery_requests%rowtype;
begin
  if coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  if p_user_id is null or p_auth_session_id is null
     or p_token_sha256 is null or p_token_sha256 !~ '^[a-f0-9]{64}$' then
    raise exception 'invalid recovery request parameters' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text || ':break-glass', 0));
  if not exists (
    select 1 from supreme.identities i
    where i.user_id = p_user_id and i.public_id = 'supreme'
      and i.role = 'ruler' and i.is_active = true
  ) then
    raise exception 'active Supreme ruler identity required' using errcode = '42501';
  end if;
  if not exists (
    select 1 from auth.sessions s
    where s.id = p_auth_session_id and s.user_id = p_user_id
      and s.not_after > now()
  ) then
    raise exception 'Auth session is not active' using errcode = '42501';
  end if;
  if exists (
    select 1 from supreme.devices d
    where d.user_id = p_user_id and d.status = 'active'
  ) then
    raise exception 'recovery is only available after all trusted devices are lost' using errcode = 'P0001';
  end if;

  select * into v_authorization
  from supreme.recovery_authorizations
  where user_id = p_user_id and token_sha256 = p_token_sha256
    and consumed_at is null and expires_at > now()
  for update;
  if not found then
    insert into supreme.audit_events(actor_user_id, action, outcome, policy_version, details)
    values (p_user_id, 'recovery.request', 'denied', 'v1',
      jsonb_build_object('reason', 'invalid_or_expired_offline_material'));
    raise exception 'offline recovery material is invalid or expired' using errcode = '42501';
  end if;

  select * into v_request
  from supreme.recovery_requests
  where user_id = p_user_id and status = 'pending'
  for update;
  if found then
    if v_request.authorization_id <> v_authorization.id then
      raise exception 'another recovery request is already pending' using errcode = 'P0001';
    end if;
    return jsonb_build_object(
      'request_id', v_request.id, 'available_at', v_request.available_at,
      'expires_at', v_request.expires_at, 'already_pending', true
    );
  end if;

  insert into supreme.recovery_requests(
    user_id, authorization_id, requester_auth_session_id
  ) values (p_user_id, v_authorization.id, p_auth_session_id)
  returning * into v_request;

  insert into supreme.recovery_notification_outbox(recovery_request_id, event_type, payload)
  values (v_request.id, 'requested', jsonb_build_object(
    'event', 'supreme.recovery.requested',
    'request_id', v_request.id,
    'requested_at', v_request.requested_at,
    'available_at', v_request.available_at
  ));

  insert into supreme.audit_events(actor_user_id, action, outcome, policy_version, details)
  values (p_user_id, 'recovery.request', 'pending', 'v1',
    jsonb_build_object('request_id', v_request.id, 'available_at', v_request.available_at));

  return jsonb_build_object(
    'request_id', v_request.id, 'available_at', v_request.available_at,
    'expires_at', v_request.expires_at, 'already_pending', false
  );
end;
$$;

create or replace function public.complete_supreme_break_glass_recovery(
  p_user_id uuid,
  p_auth_session_id uuid,
  p_request_id uuid,
  p_token_sha256 text,
  p_device_key_sha256 text,
  p_signing_certificate_sha256 text,
  p_security_level text,
  p_attested_at timestamptz,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_request supreme.recovery_requests%rowtype;
  v_authorization supreme.recovery_authorizations%rowtype;
  v_device_id uuid;
  v_session_id uuid;
  v_revoked_devices integer := 0;
  v_revoked_sessions integer := 0;
begin
  if coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  if p_user_id is null or p_auth_session_id is null or p_request_id is null
     or p_token_sha256 is null or p_token_sha256 !~ '^[a-f0-9]{64}$'
     or p_device_key_sha256 is null or p_device_key_sha256 !~ '^[a-f0-9]{64}$'
     or p_signing_certificate_sha256 is null or p_signing_certificate_sha256 !~ '^[a-f0-9]{64}$'
     or p_security_level not in ('trusted_environment', 'strongbox')
     or p_attested_at is null or p_attested_at > now()
     or p_attested_at < now() - interval '2 minutes'
     or p_expires_at <= now() or p_expires_at > now() + interval '4 hours' then
    raise exception 'invalid recovery completion parameters' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text || ':break-glass', 0));

  select * into v_request
  from supreme.recovery_requests
  where id = p_request_id and user_id = p_user_id and status = 'pending'
  for update;
  if not found or v_request.available_at > now() or v_request.expires_at <= now() then
    raise exception 'recovery request is not eligible for completion' using errcode = 'P0001';
  end if;
  if v_request.notification_sent_at is null then
    raise exception 'independent recovery notification has not been delivered' using errcode = 'P0001';
  end if;
  if v_request.requester_auth_session_id <> p_auth_session_id then
    raise exception 'recovery must be completed from the requesting Auth session' using errcode = '42501';
  end if;

  select * into v_authorization
  from supreme.recovery_authorizations
  where id = v_request.authorization_id and user_id = p_user_id
    and token_sha256 = p_token_sha256 and consumed_at is null and expires_at > now()
  for update;
  if not found then
    raise exception 'offline recovery material is invalid, expired, or consumed' using errcode = '42501';
  end if;

  if exists (
    select 1 from supreme.devices
    where user_id = p_user_id and device_key_sha256 = p_device_key_sha256
  ) then
    raise exception 'recovery requires a fresh device key' using errcode = '42501';
  end if;

  update supreme.app_sessions
  set status = 'revoked', revoked_at = now(), updated_at = now()
  where user_id = p_user_id and status = 'active';
  get diagnostics v_revoked_sessions = row_count;

  update supreme.devices
  set status = 'revoked', updated_at = now()
  where user_id = p_user_id and status = 'active';
  get diagnostics v_revoked_devices = row_count;

  insert into supreme.devices(
    user_id, device_key_sha256, app_package, signing_certificate_sha256,
    security_level, attested_at, last_seen_at, status,
    device_key_biometric_auth_required, updated_at
  ) values (
    p_user_id, p_device_key_sha256, 'com.neweix.supreme',
    p_signing_certificate_sha256, p_security_level, p_attested_at,
    now(), 'active', true, now()
  ) returning id into v_device_id;

  insert into supreme.app_sessions(
    user_id, device_id, auth_session_id, status, attested_at,
    expires_at, revoked_at, updated_at
  ) values (
    p_user_id, v_device_id, p_auth_session_id, 'active',
    p_attested_at, p_expires_at, null, now()
  ) returning id into v_session_id;

  update supreme.recovery_authorizations
  set consumed_at = now(), consumed_by_request_id = p_request_id
  where id = v_authorization.id and consumed_at is null;
  if not found then
    raise exception 'offline recovery material was already consumed' using errcode = 'P0001';
  end if;

  update supreme.recovery_requests
  set status = 'completed', completed_at = now(),
      completed_device_id = v_device_id, updated_at = now()
  where id = p_request_id and status = 'pending';
  if not found then
    raise exception 'recovery request was already completed' using errcode = 'P0001';
  end if;

  insert into supreme.recovery_notification_outbox(recovery_request_id, event_type, payload)
  values (p_request_id, 'completed', jsonb_build_object(
    'event', 'supreme.recovery.completed',
    'request_id', p_request_id,
    'completed_at', now(),
    'device_id', v_device_id
  ));

  insert into supreme.audit_events(actor_user_id, action, outcome, policy_version, details)
  values (p_user_id, 'recovery.complete', 'success', 'v1', jsonb_build_object(
    'request_id', p_request_id, 'device_id', v_device_id,
    'revoked_devices', v_revoked_devices, 'revoked_sessions', v_revoked_sessions
  ));

  return jsonb_build_object(
    'completed', true, 'device_id', v_device_id,
    'session_id', v_session_id,
    'revoked_devices', v_revoked_devices,
    'revoked_sessions', v_revoked_sessions,
    'expires_at', p_expires_at
  );
end;
$$;

create or replace function public.mark_supreme_recovery_notification_delivered(
  p_request_id uuid,
  p_event_type text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_updated integer;
begin
  if coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  if p_request_id is null or p_event_type not in ('requested', 'completed') then
    raise exception 'invalid notification acknowledgement' using errcode = '22023';
  end if;

  update supreme.recovery_notification_outbox
  set delivered_at = coalesce(delivered_at, now()),
      attempts = attempts + 1, last_error_code = null
  where recovery_request_id = p_request_id and event_type = p_event_type
    and delivered_at is null;
  get diagnostics v_updated = row_count;

  if p_event_type = 'requested' and v_updated = 1 then
    update supreme.recovery_requests
    set notification_sent_at = now(), updated_at = now()
    where id = p_request_id and status = 'pending';
  end if;
  return v_updated = 1;
end;
$$;

revoke all on function public.begin_supreme_break_glass_recovery(uuid, uuid, text)
  from public, anon, authenticated;
revoke all on function public.complete_supreme_break_glass_recovery(
  uuid, uuid, uuid, text, text, text, text, timestamptz, timestamptz
) from public, anon, authenticated;
revoke all on function public.mark_supreme_recovery_notification_delivered(uuid, text)
  from public, anon, authenticated;
grant execute on function public.begin_supreme_break_glass_recovery(uuid, uuid, text) to service_role;
grant execute on function public.complete_supreme_break_glass_recovery(
  uuid, uuid, uuid, text, text, text, text, timestamptz, timestamptz
) to service_role;
grant execute on function public.mark_supreme_recovery_notification_delivered(uuid, text) to service_role;

comment on table supreme.recovery_authorizations is
  'Single-use offline Supreme break-glass recovery material. Only SHA-256 digests are stored.';
comment on table supreme.recovery_requests is
  '24-hour cooling-off recovery requests; completion requires independent notification delivery.';
