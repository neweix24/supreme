-- Fail-closed device enrollment: new hardware keys remain pending until an
-- already trusted device approves them. Existing active devices may renew their
-- own sessions; revoked/blocked keys can never be reactivated by re-attestation.

alter table supreme.devices
  drop constraint if exists devices_status_check;
alter table supreme.devices
  add constraint devices_status_check
  check (status in ('pending_approval', 'active', 'revoked', 'blocked'));

create table if not exists supreme.device_enrollment_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete restrict,
  device_id uuid not null references supreme.devices(id) on delete restrict,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'expired')),
  requested_at timestamptz not null default now(),
  decided_at timestamptz,
  decided_by_device_id uuid references supreme.devices(id) on delete restrict,
  expires_at timestamptz not null default (now() + interval '24 hours'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((status = 'pending') = (decided_at is null)),
  check (expires_at > requested_at)
);

create unique index if not exists supreme_one_pending_enrollment_per_device
  on supreme.device_enrollment_requests(device_id) where status = 'pending';
create index if not exists supreme_pending_enrollments_user_idx
  on supreme.device_enrollment_requests(user_id, requested_at desc)
  where status = 'pending';

alter table supreme.device_enrollment_requests enable row level security;
revoke all on table supreme.device_enrollment_requests from public, anon, authenticated;
grant select, insert, update, delete on table supreme.device_enrollment_requests to service_role;

create or replace function public.register_supreme_attested_device_session(
  p_user_id uuid,
  p_auth_session_id uuid,
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
  v_device_id uuid;
  v_device_status text;
  v_session_id uuid;
begin
  if coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;

  if p_user_id is null
     or p_auth_session_id is null
     or p_device_key_sha256 is null
     or p_device_key_sha256 !~ '^[a-f0-9]{64}
     or p_attested_at > now()
     or p_attested_at < now() - interval '2 minutes'
     or p_expires_at <= now()
     or p_expires_at > now() + interval '12 hours' then
    raise exception 'invalid Supreme device registration parameters'
      using errcode = '22023';
  end if;

  if not exists (
    select 1 from supreme.identities i
    where i.user_id = p_user_id
      and i.public_id = 'supreme'
      and i.role = 'ruler'
      and i.is_active = true
  ) then
    raise exception 'active Supreme ruler identity required'
      using errcode = '42501';
  end if;

  -- Serialize even the absent-key case so concurrent first attestations cannot race
  -- into the unique constraint or create inconsistent enrollment requests.
  perform pg_advisory_xact_lock(
    hashtextextended(p_user_id::text || ':' || p_device_key_sha256, 0)
  );

  -- Serialize registration for this user/key. Never revive a revoked or blocked key.
  select d.id, d.status
    into v_device_id, v_device_status
  from supreme.devices d
  where d.user_id = p_user_id
    and d.device_key_sha256 = p_device_key_sha256
  for update;

  if v_device_id is not null and v_device_status in ('revoked', 'blocked') then
    raise exception 'device key is permanently denied; use recovery enrollment'
      using errcode = '42501';
  end if;

  if v_device_id is null then
    insert into supreme.devices (
      user_id, device_key_sha256, app_package, signing_certificate_sha256,
      security_level, attested_at, last_seen_at, status, updated_at
    ) values (
      p_user_id, p_device_key_sha256, 'com.neweix.supreme',
      p_signing_certificate_sha256, p_security_level, p_attested_at,
      now(), 'pending_approval', now()
    ) returning id into v_device_id;

    insert into supreme.device_enrollment_requests (user_id, device_id)
    values (p_user_id, v_device_id);

    insert into supreme.audit_events (
      actor_user_id, action, outcome, policy_version, details
    ) values (
      p_user_id, 'device_enrollment.request', 'pending', 'v1',
      jsonb_build_object('device_id', v_device_id, 'security_level', p_security_level)
    );

    return jsonb_build_object(
      'registered', true,
      'pending_approval', true,
      'device_id', v_device_id
    );
  end if;

  -- Repeated attestation of a pending key is idempotent: it remains pending
  -- and receives no app session until an explicit trusted-device approval.
  if v_device_status = 'pending_approval' then
    update supreme.devices
    set signing_certificate_sha256 = p_signing_certificate_sha256,
        security_level = p_security_level,
        attested_at = p_attested_at,
        last_seen_at = now(),
        updated_at = now()
    where id = v_device_id and status = 'pending_approval';

    return jsonb_build_object(
      'registered', true,
      'pending_approval', true,
      'device_id', v_device_id
    );
  end if;

  -- Only a previously active device can renew its own session.
  update supreme.devices
  set signing_certificate_sha256 = p_signing_certificate_sha256,
      security_level = p_security_level,
      attested_at = p_attested_at,
      last_seen_at = now(),
      updated_at = now()
  where id = v_device_id and status = 'active';

  insert into supreme.app_sessions (
    user_id, device_id, auth_session_id, status, attested_at,
    expires_at, revoked_at, updated_at
  ) values (
    p_user_id, v_device_id, p_auth_session_id, 'active',
    p_attested_at, p_expires_at, null, now()
  )
  on conflict (auth_session_id) do update set
    user_id = excluded.user_id,
    device_id = excluded.device_id,
    status = 'active',
    attested_at = excluded.attested_at,
    expires_at = excluded.expires_at,
    revoked_at = null,
    updated_at = now()
  where app_sessions.status = 'active'
    and app_sessions.user_id = excluded.user_id
    and app_sessions.device_id = excluded.device_id
  returning id into v_session_id;

  if v_session_id is null then
    raise exception 'auth session was previously revoked and cannot be reactivated'
      using errcode = '42501';
  end if;

  insert into supreme.audit_events (
    actor_user_id, action, outcome, policy_version, details
  ) values (
    p_user_id, 'device_session.register', 'success', 'v1',
    jsonb_build_object(
      'session_id', v_session_id,
      'device_id', v_device_id,
      'security_level', p_security_level,
      'app_package', 'com.neweix.supreme'
    )
  );

  return jsonb_build_object(
    'registered', true,
    'pending_approval', false,
    'session_id', v_session_id,
    'device_id', v_device_id,
    'expires_at', p_expires_at
  );
end;
$$;

revoke all on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz
) from public, anon, authenticated;
grant execute on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz
) to service_role;

comment on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz
) is 'Registers an already-active attested device session or creates a pending enrollment; revoked and blocked device keys are never reactivated.';


-- One-time biometric approval challenges. Only the service role can access
-- these rows; the registered approver public key is loaded server-side.
create table if not exists supreme.device_enrollment_approval_challenges (
  id uuid primary key default gen_random_uuid(),
  enrollment_request_id uuid not null references supreme.device_enrollment_requests(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete restrict,
  approving_device_id uuid not null references supreme.devices(id) on delete restrict,
  approving_auth_session_id uuid not null,
  nonce_sha256 bytea not null check (octet_length(nonce_sha256) = 32),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at)
);

create index if not exists supreme_enrollment_approval_rate_idx
  on supreme.device_enrollment_approval_challenges(user_id, approving_device_id, created_at desc);

alter table supreme.device_enrollment_approval_challenges enable row level security;
revoke all on table supreme.device_enrollment_approval_challenges from public, anon, authenticated;
grant select, insert, update, delete on table supreme.device_enrollment_approval_challenges to service_role;

create or replace function public.approve_supreme_device_enrollment(
  p_enrollment_request_id uuid,
  p_challenge_id uuid,
  p_user_id uuid,
  p_approving_device_id uuid,
  p_approving_auth_session_id uuid,
  p_nonce_sha256 bytea
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_challenge supreme.device_enrollment_approval_challenges%rowtype;
  v_request supreme.device_enrollment_requests%rowtype;
begin
  if coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  if p_enrollment_request_id is null or p_challenge_id is null or p_user_id is null
     or p_approving_device_id is null or p_approving_auth_session_id is null
     or p_nonce_sha256 is null
     or octet_length(p_nonce_sha256) <> 32 then
    raise exception 'invalid approval parameters' using errcode = '22023';
  end if;

  select * into v_challenge
  from supreme.device_enrollment_approval_challenges
  where id = p_challenge_id
    and enrollment_request_id = p_enrollment_request_id
    and user_id = p_user_id
    and approving_device_id = p_approving_device_id
    and approving_auth_session_id = p_approving_auth_session_id
    and nonce_sha256 = p_nonce_sha256
    and expires_at > now()
    and consumed_at is null
  for update;

  if not found then
    raise exception 'approval challenge invalid, expired, or consumed' using errcode = 'P0001';
  end if;

  select * into v_request
  from supreme.device_enrollment_requests
  where id = p_enrollment_request_id
    and user_id = p_user_id
    and status = 'pending'
    and expires_at > now()
  for update;

  if not found then
    raise exception 'enrollment request is no longer pending' using errcode = 'P0001';
  end if;

  if not exists (
    select 1
    from supreme.app_sessions s
    join supreme.devices d on d.id = s.device_id
    where s.auth_session_id = p_approving_auth_session_id
      and s.user_id = p_user_id
      and s.device_id = p_approving_device_id
      and s.status = 'active'
      and s.expires_at > now()
      and d.status = 'active'
      and d.device_key_biometric_auth_required = true
      and d.device_public_key_spki is not null
  ) then
    raise exception 'approving device session is no longer active' using errcode = '42501';
  end if;

  if not exists (
    select 1 from supreme.devices d
    where d.id = p_approving_device_id
      and d.user_id = p_user_id
      and d.status = 'active'
      and d.device_key_biometric_auth_required = true
      and d.device_public_key_spki is not null
  ) then
    raise exception 'approving device is not trusted' using errcode = '42501';
  end if;

  if not exists (
    select 1 from supreme.devices d
    where d.id = v_request.device_id
      and d.user_id = p_user_id
      and d.status = 'pending_approval'
      and d.id <> p_approving_device_id
  ) then
    raise exception 'target device is not pending approval' using errcode = 'P0001';
  end if;

  update supreme.device_enrollment_approval_challenges
  set consumed_at = now()
  where id = p_challenge_id and consumed_at is null and expires_at > now();
  if not found then
    raise exception 'approval challenge replayed' using errcode = 'P0001';
  end if;

  update supreme.device_enrollment_requests
  set status = 'approved', decided_at = now(),
      decided_by_device_id = p_approving_device_id, updated_at = now()
  where id = p_enrollment_request_id and status = 'pending';
  if not found then
    raise exception 'enrollment request changed during approval' using errcode = 'P0001';
  end if;

  update supreme.devices
  set status = 'active', updated_at = now()
  where id = v_request.device_id and status = 'pending_approval';
  if not found then
    raise exception 'target device state changed during approval' using errcode = 'P0001';
  end if;

  insert into supreme.audit_events (
    actor_user_id, action, outcome, policy_version, details
  ) values (
    p_user_id, 'device_enrollment.approve', 'success', 'v1',
    jsonb_build_object(
      'enrollment_request_id', p_enrollment_request_id,
      'device_id', v_request.device_id,
      'approving_device_id', p_approving_device_id,
      'challenge_id', p_challenge_id
    )
  );

  return jsonb_build_object(
    'approved', true,
    'enrollment_request_id', p_enrollment_request_id,
    'device_id', v_request.device_id
  );
end;
$$;

revoke all on function public.approve_supreme_device_enrollment(uuid, uuid, uuid, uuid, uuid, bytea)
  from public, anon, authenticated;
grant execute on function public.approve_supreme_device_enrollment(uuid, uuid, uuid, uuid, bytea)
  to service_role;

     or p_signing_certificate_sha256 is null
     or p_signing_certificate_sha256 !~ '^[a-f0-9]{64}
     or p_attested_at > now()
     or p_attested_at < now() - interval '2 minutes'
     or p_expires_at <= now()
     or p_expires_at > now() + interval '12 hours' then
    raise exception 'invalid Supreme device registration parameters'
      using errcode = '22023';
  end if;

  if not exists (
    select 1 from supreme.identities i
    where i.user_id = p_user_id
      and i.public_id = 'supreme'
      and i.role = 'ruler'
      and i.is_active = true
  ) then
    raise exception 'active Supreme ruler identity required'
      using errcode = '42501';
  end if;

  -- Serialize registration for this user/key. Never revive a revoked or blocked key.
  select d.id, d.status
    into v_device_id, v_device_status
  from supreme.devices d
  where d.user_id = p_user_id
    and d.device_key_sha256 = p_device_key_sha256
  for update;

  if v_device_id is not null and v_device_status in ('revoked', 'blocked') then
    raise exception 'device key is permanently denied; use recovery enrollment'
      using errcode = '42501';
  end if;

  if v_device_id is null then
    insert into supreme.devices (
      user_id, device_key_sha256, app_package, signing_certificate_sha256,
      security_level, attested_at, last_seen_at, status, updated_at
    ) values (
      p_user_id, p_device_key_sha256, 'com.neweix.supreme',
      p_signing_certificate_sha256, p_security_level, p_attested_at,
      now(), 'pending_approval', now()
    ) returning id into v_device_id;

    insert into supreme.device_enrollment_requests (user_id, device_id)
    values (p_user_id, v_device_id);

    insert into supreme.audit_events (
      actor_user_id, action, outcome, policy_version, details
    ) values (
      p_user_id, 'device_enrollment.request', 'pending', 'v1',
      jsonb_build_object('device_id', v_device_id, 'security_level', p_security_level)
    );

    return jsonb_build_object(
      'registered', true,
      'pending_approval', true,
      'device_id', v_device_id
    );
  end if;

  -- Repeated attestation of a pending key is idempotent: it remains pending
  -- and receives no app session until an explicit trusted-device approval.
  if v_device_status = 'pending_approval' then
    update supreme.devices
    set signing_certificate_sha256 = p_signing_certificate_sha256,
        security_level = p_security_level,
        attested_at = p_attested_at,
        last_seen_at = now(),
        updated_at = now()
    where id = v_device_id and status = 'pending_approval';

    return jsonb_build_object(
      'registered', true,
      'pending_approval', true,
      'device_id', v_device_id
    );
  end if;

  -- Only a previously active device can renew its own session.
  update supreme.devices
  set signing_certificate_sha256 = p_signing_certificate_sha256,
      security_level = p_security_level,
      attested_at = p_attested_at,
      last_seen_at = now(),
      updated_at = now()
  where id = v_device_id and status = 'active';

  insert into supreme.app_sessions (
    user_id, device_id, auth_session_id, status, attested_at,
    expires_at, revoked_at, updated_at
  ) values (
    p_user_id, v_device_id, p_auth_session_id, 'active',
    p_attested_at, p_expires_at, null, now()
  )
  on conflict (auth_session_id) do update set
    user_id = excluded.user_id,
    device_id = excluded.device_id,
    status = 'active',
    attested_at = excluded.attested_at,
    expires_at = excluded.expires_at,
    revoked_at = null,
    updated_at = now()
  where app_sessions.status = 'active'
  returning id into v_session_id;

  if v_session_id is null then
    raise exception 'auth session was previously revoked and cannot be reactivated'
      using errcode = '42501';
  end if;

  insert into supreme.audit_events (
    actor_user_id, action, outcome, policy_version, details
  ) values (
    p_user_id, 'device_session.register', 'success', 'v1',
    jsonb_build_object(
      'session_id', v_session_id,
      'device_id', v_device_id,
      'security_level', p_security_level,
      'app_package', 'com.neweix.supreme'
    )
  );

  return jsonb_build_object(
    'registered', true,
    'pending_approval', false,
    'session_id', v_session_id,
    'device_id', v_device_id,
    'expires_at', p_expires_at
  );
end;
$$;

revoke all on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz
) from public, anon, authenticated;
grant execute on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz
) to service_role;

comment on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz
) is 'Registers an already-active attested device session or creates a pending enrollment; revoked and blocked device keys are never reactivated.';


-- One-time biometric approval challenges. Only the service role can access
-- these rows; the registered approver public key is loaded server-side.
create table if not exists supreme.device_enrollment_approval_challenges (
  id uuid primary key default gen_random_uuid(),
  enrollment_request_id uuid not null references supreme.device_enrollment_requests(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete restrict,
  approving_device_id uuid not null references supreme.devices(id) on delete restrict,
  nonce_sha256 bytea not null check (octet_length(nonce_sha256) = 32),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at)
);

create index if not exists supreme_enrollment_approval_rate_idx
  on supreme.device_enrollment_approval_challenges(user_id, approving_device_id, created_at desc);

alter table supreme.device_enrollment_approval_challenges enable row level security;
revoke all on table supreme.device_enrollment_approval_challenges from public, anon, authenticated;
grant select, insert, update, delete on table supreme.device_enrollment_approval_challenges to service_role;

create or replace function public.approve_supreme_device_enrollment(
  p_enrollment_request_id uuid,
  p_challenge_id uuid,
  p_user_id uuid,
  p_approving_device_id uuid,
  p_nonce_sha256 bytea
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_challenge supreme.device_enrollment_approval_challenges%rowtype;
  v_request supreme.device_enrollment_requests%rowtype;
begin
  if coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  if p_enrollment_request_id is null or p_challenge_id is null or p_user_id is null
     or p_approving_device_id is null or p_nonce_sha256 is null
     or octet_length(p_nonce_sha256) <> 32 then
    raise exception 'invalid approval parameters' using errcode = '22023';
  end if;

  select * into v_challenge
  from supreme.device_enrollment_approval_challenges
  where id = p_challenge_id
    and enrollment_request_id = p_enrollment_request_id
    and user_id = p_user_id
    and approving_device_id = p_approving_device_id
    and nonce_sha256 = p_nonce_sha256
    and expires_at > now()
    and consumed_at is null
  for update;

  if not found then
    raise exception 'approval challenge invalid, expired, or consumed' using errcode = 'P0001';
  end if;

  select * into v_request
  from supreme.device_enrollment_requests
  where id = p_enrollment_request_id
    and user_id = p_user_id
    and status = 'pending'
    and expires_at > now()
  for update;

  if not found then
    raise exception 'enrollment request is no longer pending' using errcode = 'P0001';
  end if;

  if not exists (
    select 1 from supreme.devices d
    where d.id = p_approving_device_id
      and d.user_id = p_user_id
      and d.status = 'active'
      and d.device_key_biometric_auth_required = true
      and d.device_public_key_spki is not null
  ) then
    raise exception 'approving device is not trusted' using errcode = '42501';
  end if;

  if not exists (
    select 1 from supreme.devices d
    where d.id = v_request.device_id
      and d.user_id = p_user_id
      and d.status = 'pending_approval'
      and d.id <> p_approving_device_id
  ) then
    raise exception 'target device is not pending approval' using errcode = 'P0001';
  end if;

  update supreme.device_enrollment_approval_challenges
  set consumed_at = now()
  where id = p_challenge_id and consumed_at is null and expires_at > now();
  if not found then
    raise exception 'approval challenge replayed' using errcode = 'P0001';
  end if;

  update supreme.device_enrollment_requests
  set status = 'approved', decided_at = now(),
      decided_by_device_id = p_approving_device_id, updated_at = now()
  where id = p_enrollment_request_id and status = 'pending';
  if not found then
    raise exception 'enrollment request changed during approval' using errcode = 'P0001';
  end if;

  update supreme.devices
  set status = 'active', updated_at = now()
  where id = v_request.device_id and status = 'pending_approval';
  if not found then
    raise exception 'target device state changed during approval' using errcode = 'P0001';
  end if;

  insert into supreme.audit_events (
    actor_user_id, action, outcome, policy_version, details
  ) values (
    p_user_id, 'device_enrollment.approve', 'success', 'v1',
    jsonb_build_object(
      'enrollment_request_id', p_enrollment_request_id,
      'device_id', v_request.device_id,
      'approving_device_id', p_approving_device_id,
      'challenge_id', p_challenge_id
    )
  );

  return jsonb_build_object(
    'approved', true,
    'enrollment_request_id', p_enrollment_request_id,
    'device_id', v_request.device_id
  );
end;
$$;

revoke all on function public.approve_supreme_device_enrollment(uuid, uuid, uuid, uuid, bytea)
  from public, anon, authenticated;
grant execute on function public.approve_supreme_device_enrollment(uuid, uuid, uuid, uuid, bytea)
  to service_role;

     or p_security_level is null
     or p_security_level not in ('trusted_environment', 'strongbox')
     or p_attested_at is null
     or p_expires_at is null
     or p_attested_at > now()
     or p_attested_at < now() - interval '2 minutes'
     or p_expires_at <= now()
     or p_expires_at > now() + interval '12 hours' then
    raise exception 'invalid Supreme device registration parameters'
      using errcode = '22023';
  end if;

  if not exists (
    select 1 from supreme.identities i
    where i.user_id = p_user_id
      and i.public_id = 'supreme'
      and i.role = 'ruler'
      and i.is_active = true
  ) then
    raise exception 'active Supreme ruler identity required'
      using errcode = '42501';
  end if;

  -- Serialize registration for this user/key. Never revive a revoked or blocked key.
  select d.id, d.status
    into v_device_id, v_device_status
  from supreme.devices d
  where d.user_id = p_user_id
    and d.device_key_sha256 = p_device_key_sha256
  for update;

  if v_device_id is not null and v_device_status in ('revoked', 'blocked') then
    raise exception 'device key is permanently denied; use recovery enrollment'
      using errcode = '42501';
  end if;

  if v_device_id is null then
    insert into supreme.devices (
      user_id, device_key_sha256, app_package, signing_certificate_sha256,
      security_level, attested_at, last_seen_at, status, updated_at
    ) values (
      p_user_id, p_device_key_sha256, 'com.neweix.supreme',
      p_signing_certificate_sha256, p_security_level, p_attested_at,
      now(), 'pending_approval', now()
    ) returning id into v_device_id;

    insert into supreme.device_enrollment_requests (user_id, device_id)
    values (p_user_id, v_device_id);

    insert into supreme.audit_events (
      actor_user_id, action, outcome, policy_version, details
    ) values (
      p_user_id, 'device_enrollment.request', 'pending', 'v1',
      jsonb_build_object('device_id', v_device_id, 'security_level', p_security_level)
    );

    return jsonb_build_object(
      'registered', true,
      'pending_approval', true,
      'device_id', v_device_id
    );
  end if;

  -- Repeated attestation of a pending key is idempotent: it remains pending
  -- and receives no app session until an explicit trusted-device approval.
  if v_device_status = 'pending_approval' then
    update supreme.devices
    set signing_certificate_sha256 = p_signing_certificate_sha256,
        security_level = p_security_level,
        attested_at = p_attested_at,
        last_seen_at = now(),
        updated_at = now()
    where id = v_device_id and status = 'pending_approval';

    return jsonb_build_object(
      'registered', true,
      'pending_approval', true,
      'device_id', v_device_id
    );
  end if;

  -- Only a previously active device can renew its own session.
  update supreme.devices
  set signing_certificate_sha256 = p_signing_certificate_sha256,
      security_level = p_security_level,
      attested_at = p_attested_at,
      last_seen_at = now(),
      updated_at = now()
  where id = v_device_id and status = 'active';

  insert into supreme.app_sessions (
    user_id, device_id, auth_session_id, status, attested_at,
    expires_at, revoked_at, updated_at
  ) values (
    p_user_id, v_device_id, p_auth_session_id, 'active',
    p_attested_at, p_expires_at, null, now()
  )
  on conflict (auth_session_id) do update set
    user_id = excluded.user_id,
    device_id = excluded.device_id,
    status = 'active',
    attested_at = excluded.attested_at,
    expires_at = excluded.expires_at,
    revoked_at = null,
    updated_at = now()
  where app_sessions.status = 'active'
  returning id into v_session_id;

  if v_session_id is null then
    raise exception 'auth session was previously revoked and cannot be reactivated'
      using errcode = '42501';
  end if;

  insert into supreme.audit_events (
    actor_user_id, action, outcome, policy_version, details
  ) values (
    p_user_id, 'device_session.register', 'success', 'v1',
    jsonb_build_object(
      'session_id', v_session_id,
      'device_id', v_device_id,
      'security_level', p_security_level,
      'app_package', 'com.neweix.supreme'
    )
  );

  return jsonb_build_object(
    'registered', true,
    'pending_approval', false,
    'session_id', v_session_id,
    'device_id', v_device_id,
    'expires_at', p_expires_at
  );
end;
$$;

revoke all on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz
) from public, anon, authenticated;
grant execute on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz
) to service_role;

comment on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz
) is 'Registers an already-active attested device session or creates a pending enrollment; revoked and blocked device keys are never reactivated.';


-- One-time biometric approval challenges. Only the service role can access
-- these rows; the registered approver public key is loaded server-side.
create table if not exists supreme.device_enrollment_approval_challenges (
  id uuid primary key default gen_random_uuid(),
  enrollment_request_id uuid not null references supreme.device_enrollment_requests(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete restrict,
  approving_device_id uuid not null references supreme.devices(id) on delete restrict,
  nonce_sha256 bytea not null check (octet_length(nonce_sha256) = 32),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at)
);

create index if not exists supreme_enrollment_approval_rate_idx
  on supreme.device_enrollment_approval_challenges(user_id, approving_device_id, created_at desc);

alter table supreme.device_enrollment_approval_challenges enable row level security;
revoke all on table supreme.device_enrollment_approval_challenges from public, anon, authenticated;
grant select, insert, update, delete on table supreme.device_enrollment_approval_challenges to service_role;

create or replace function public.approve_supreme_device_enrollment(
  p_enrollment_request_id uuid,
  p_challenge_id uuid,
  p_user_id uuid,
  p_approving_device_id uuid,
  p_nonce_sha256 bytea
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_challenge supreme.device_enrollment_approval_challenges%rowtype;
  v_request supreme.device_enrollment_requests%rowtype;
begin
  if coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  if p_enrollment_request_id is null or p_challenge_id is null or p_user_id is null
     or p_approving_device_id is null or p_nonce_sha256 is null
     or octet_length(p_nonce_sha256) <> 32 then
    raise exception 'invalid approval parameters' using errcode = '22023';
  end if;

  select * into v_challenge
  from supreme.device_enrollment_approval_challenges
  where id = p_challenge_id
    and enrollment_request_id = p_enrollment_request_id
    and user_id = p_user_id
    and approving_device_id = p_approving_device_id
    and nonce_sha256 = p_nonce_sha256
    and expires_at > now()
    and consumed_at is null
  for update;

  if not found then
    raise exception 'approval challenge invalid, expired, or consumed' using errcode = 'P0001';
  end if;

  select * into v_request
  from supreme.device_enrollment_requests
  where id = p_enrollment_request_id
    and user_id = p_user_id
    and status = 'pending'
    and expires_at > now()
  for update;

  if not found then
    raise exception 'enrollment request is no longer pending' using errcode = 'P0001';
  end if;

  if not exists (
    select 1 from supreme.devices d
    where d.id = p_approving_device_id
      and d.user_id = p_user_id
      and d.status = 'active'
      and d.device_key_biometric_auth_required = true
      and d.device_public_key_spki is not null
  ) then
    raise exception 'approving device is not trusted' using errcode = '42501';
  end if;

  if not exists (
    select 1 from supreme.devices d
    where d.id = v_request.device_id
      and d.user_id = p_user_id
      and d.status = 'pending_approval'
      and d.id <> p_approving_device_id
  ) then
    raise exception 'target device is not pending approval' using errcode = 'P0001';
  end if;

  update supreme.device_enrollment_approval_challenges
  set consumed_at = now()
  where id = p_challenge_id and consumed_at is null and expires_at > now();
  if not found then
    raise exception 'approval challenge replayed' using errcode = 'P0001';
  end if;

  update supreme.device_enrollment_requests
  set status = 'approved', decided_at = now(),
      decided_by_device_id = p_approving_device_id, updated_at = now()
  where id = p_enrollment_request_id and status = 'pending';
  if not found then
    raise exception 'enrollment request changed during approval' using errcode = 'P0001';
  end if;

  update supreme.devices
  set status = 'active', updated_at = now()
  where id = v_request.device_id and status = 'pending_approval';
  if not found then
    raise exception 'target device state changed during approval' using errcode = 'P0001';
  end if;

  insert into supreme.audit_events (
    actor_user_id, action, outcome, policy_version, details
  ) values (
    p_user_id, 'device_enrollment.approve', 'success', 'v1',
    jsonb_build_object(
      'enrollment_request_id', p_enrollment_request_id,
      'device_id', v_request.device_id,
      'approving_device_id', p_approving_device_id,
      'challenge_id', p_challenge_id
    )
  );

  return jsonb_build_object(
    'approved', true,
    'enrollment_request_id', p_enrollment_request_id,
    'device_id', v_request.device_id
  );
end;
$$;

revoke all on function public.approve_supreme_device_enrollment(uuid, uuid, uuid, uuid, bytea)
  from public, anon, authenticated;
grant execute on function public.approve_supreme_device_enrollment(uuid, uuid, uuid, uuid, bytea)
  to service_role;
