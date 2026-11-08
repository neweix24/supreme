-- Supreme trusted-device inventory and biometric remote revocation.
-- A revocation is bound to one fresh-AAL2 Auth session and one biometric signature.
-- Revoking a device atomically revokes every app session belonging to that device.

create table if not exists supreme.device_management_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete restrict,
  action text not null check (action = 'revoke_device'),
  target_device_id uuid not null references supreme.devices(id) on delete restrict,
  approving_device_id uuid not null references supreme.devices(id) on delete restrict,
  approving_auth_session_id uuid not null,
  nonce_sha256 bytea not null check (octet_length(nonce_sha256) = 32),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  check (expires_at > created_at),
  check (consumed_at is null or consumed_at >= created_at),
  check (target_device_id <> approving_device_id)
);

create index if not exists supreme_device_management_challenge_rate_idx
  on supreme.device_management_challenges(user_id, approving_device_id, created_at desc);

alter table supreme.device_management_challenges enable row level security;
revoke all on table supreme.device_management_challenges from public, anon, authenticated;
grant select, insert, update, delete on table supreme.device_management_challenges to service_role;

create or replace function public.revoke_supreme_device(
  p_user_id uuid,
  p_target_device_id uuid,
  p_challenge_id uuid,
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
  v_challenge supreme.device_management_challenges%rowtype;
  v_target supreme.devices%rowtype;
  v_revoked_sessions integer := 0;
begin
  if coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  if p_user_id is null or p_target_device_id is null or p_challenge_id is null
     or p_approving_device_id is null or p_approving_auth_session_id is null
     or p_nonce_sha256 is null or octet_length(p_nonce_sha256) <> 32
     or p_target_device_id = p_approving_device_id then
    raise exception 'invalid device revocation parameters' using errcode = '22023';
  end if;

  select * into v_challenge
  from supreme.device_management_challenges
  where id = p_challenge_id
    and user_id = p_user_id
    and action = 'revoke_device'
    and target_device_id = p_target_device_id
    and approving_device_id = p_approving_device_id
    and approving_auth_session_id = p_approving_auth_session_id
    and nonce_sha256 = p_nonce_sha256
    and expires_at > now()
    and consumed_at is null
  for update;
  if not found then
    raise exception 'device management challenge invalid, expired, or consumed'
      using errcode = 'P0001';
  end if;

  perform 1
  from supreme.devices
  where id = p_approving_device_id
    and user_id = p_user_id
    and status = 'active'
    and device_key_biometric_auth_required = true
    and device_public_key_spki is not null
  for update;
  if not found then
    raise exception 'approving device is not trusted' using errcode = '42501';
  end if;

  if not exists (
    select 1 from supreme.app_sessions s
    where s.user_id = p_user_id
      and s.device_id = p_approving_device_id
      and s.auth_session_id = p_approving_auth_session_id
      and s.status = 'active'
      and s.expires_at > now()
  ) then
    raise exception 'approving Auth session is no longer active' using errcode = '42501';
  end if;

  select * into v_target
  from supreme.devices
  where id = p_target_device_id
    and user_id = p_user_id
  for update;
  if not found or v_target.status <> 'active' then
    raise exception 'target device is not active' using errcode = 'P0001';
  end if;

  update supreme.device_management_challenges
  set consumed_at = now()
  where id = p_challenge_id
    and consumed_at is null
    and expires_at > now();
  if not found then
    raise exception 'device revocation challenge replayed' using errcode = 'P0001';
  end if;

  update supreme.devices
  set status = 'revoked', updated_at = now()
  where id = p_target_device_id
    and user_id = p_user_id
    and status = 'active';
  if not found then
    raise exception 'target device state changed during revocation' using errcode = 'P0001';
  end if;

  update supreme.app_sessions
  set status = 'revoked', revoked_at = now(), updated_at = now()
  where device_id = p_target_device_id
    and user_id = p_user_id
    and status = 'active';
  get diagnostics v_revoked_sessions = row_count;

  insert into supreme.audit_events (
    actor_user_id, action, outcome, policy_version, details
  ) values (
    p_user_id, 'device.revoke_remote', 'success', 'v1',
    jsonb_build_object(
      'target_device_id', p_target_device_id,
      'approving_device_id', p_approving_device_id,
      'approving_auth_session_id', p_approving_auth_session_id,
      'challenge_id', p_challenge_id,
      'revoked_sessions', v_revoked_sessions
    )
  );

  return jsonb_build_object(
    'revoked', true,
    'device_id', p_target_device_id,
    'revoked_sessions', v_revoked_sessions
  );
end;
$$;

revoke all on function public.revoke_supreme_device(
  uuid, uuid, uuid, uuid, uuid, bytea
) from public, anon, authenticated;
grant execute on function public.revoke_supreme_device(
  uuid, uuid, uuid, uuid, uuid, bytea
) to service_role;
