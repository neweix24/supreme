-- Fixes two regressions in the migration history:
--  1. 20261108010001 re-created the access-token hook WITHOUT the AAL2 check
--     added by 20261107220000.
--  2. 20261113070000 raised the device-session cap back from 4 to 12 hours.
-- The hook cap is measured from the latest attestation (attested_at) so a
-- legitimate re-attestation of the same Auth session is not silently stripped.

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
  uuid_re constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
begin
  claims := coalesce(event -> 'claims', '{}'::jsonb);

  if coalesce(claims ->> 'aal', '') <> 'aal2'
     or coalesce(event ->> 'user_id', '') !~* uuid_re
     or coalesce(claims ->> 'session_id', '') !~* uuid_re then
    claims := claims - 'supreme_app_session';
    return jsonb_set(event, '{claims}', claims, true);
  end if;
  event_user_id := (event ->> 'user_id')::uuid;
  event_session_id := (claims ->> 'session_id')::uuid;

  if not exists (
    select 1 from supreme.identities i
    where i.user_id = event_user_id and i.public_id = 'supreme'
      and i.role = 'ruler' and i.is_active = true
  ) then
    claims := claims - 'supreme_app_session';
    return jsonb_set(event, '{claims}', claims, true);
  end if;

  select s.id as session_id, s.device_id,
         extract(epoch from d.attested_at)::bigint as attested_at
    into session_row
    from supreme.app_sessions s
    join supreme.devices d on d.id = s.device_id
   where s.user_id = event_user_id
     and s.auth_session_id = event_session_id
     and s.status = 'active'
     and s.expires_at > now()
     and s.expires_at <= s.attested_at + interval '4 hours'
     and d.user_id = event_user_id
     and d.status = 'active'
     and d.app_package = 'com.neweix.supreme'
     and d.attested_at <= now()
     and d.attested_at > now() - interval '30 days'
   limit 1;

  if session_row.session_id is null then
    claims := claims - 'supreme_app_session';
  else
    claims := jsonb_set(claims, '{supreme_app_session}',
      jsonb_build_object('status', 'active', 'session_id', session_row.session_id,
                         'device_id', session_row.device_id,
                         'attested_at', session_row.attested_at), true);
  end if;
  return jsonb_set(event, '{claims}', claims, true);
end;
$$;

revoke all on function public.supreme_custom_access_token_hook(jsonb) from public, anon, authenticated;
grant execute on function public.supreme_custom_access_token_hook(jsonb) to supabase_auth_admin;

-- Re-apply the register function with the 4 hour cap and the role-claim compat.
create or replace function public.register_supreme_attested_device_session(
  p_user_id uuid, p_auth_session_id uuid, p_device_key_sha256 text,
  p_signing_certificate_sha256 text, p_security_level text,
  p_attested_at timestamptz, p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_device_id uuid;
  v_session_id uuid;
  v_request_role text;
begin
  v_request_role := coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role',
    nullif(current_setting('role', true), '')
  );
  if coalesce(v_request_role, '') <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;

  if p_user_id is null or p_auth_session_id is null
     or p_device_key_sha256 !~ '^[a-f0-9]{64}$'
     or p_signing_certificate_sha256 !~ '^[a-f0-9]{64}$'
     or p_security_level not in ('trusted_environment', 'strongbox')
     or p_attested_at is null
     or p_attested_at > now()
     or p_attested_at < now() - interval '2 minutes'
     or p_expires_at <= now()
     or p_expires_at > now() + interval '4 hours' then
    raise exception 'invalid Supreme device registration parameters' using errcode = '22023';
  end if;

  if not exists (
    select 1 from supreme.identities i
    where i.user_id = p_user_id and i.public_id = 'supreme'
      and i.role = 'ruler' and i.is_active = true
  ) then
    raise exception 'active Supreme ruler identity required' using errcode = '42501';
  end if;

  insert into supreme.devices (
    user_id, device_key_sha256, app_package, signing_certificate_sha256,
    security_level, attested_at, last_seen_at, status, updated_at
  ) values (
    p_user_id, p_device_key_sha256, 'com.neweix.supreme',
    p_signing_certificate_sha256, p_security_level, p_attested_at, now(), 'active', now()
  )
  on conflict (user_id, device_key_sha256) do update set
    signing_certificate_sha256 = excluded.signing_certificate_sha256,
    security_level = excluded.security_level,
    attested_at = excluded.attested_at,
    last_seen_at = now(), status = 'active', updated_at = now()
  returning id into v_device_id;

  insert into supreme.app_sessions (
    user_id, device_id, auth_session_id, status, attested_at, expires_at, revoked_at, updated_at
  ) values (
    p_user_id, v_device_id, p_auth_session_id, 'active', p_attested_at, p_expires_at, null, now()
  )
  on conflict (auth_session_id) do update set
    user_id = excluded.user_id, device_id = excluded.device_id, status = 'active',
    attested_at = excluded.attested_at, expires_at = excluded.expires_at,
    revoked_at = null, updated_at = now()
  returning id into v_session_id;

  insert into supreme.audit_events (actor_user_id, action, outcome, policy_version, details)
  values (p_user_id, 'device_session.register', 'success', 'v1',
    jsonb_build_object('session_id', v_session_id, 'device_id', v_device_id,
      'security_level', p_security_level, 'app_package', 'com.neweix.supreme'));

  return jsonb_build_object('registered', true, 'session_id', v_session_id,
    'device_id', v_device_id, 'expires_at', p_expires_at);
end;
$$;

revoke all on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz) from public, anon, authenticated;
grant execute on function public.register_supreme_attested_device_session(
  uuid, uuid, text, text, text, timestamptz, timestamptz) to service_role;
