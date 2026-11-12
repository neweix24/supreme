-- Regression tests for the Supreme app-bound request-signature schema.
do $$
declare
  v_user_id uuid := gen_random_uuid();
  v_device_id uuid := gen_random_uuid();
  v_session_id uuid := gen_random_uuid();
  v_challenge_id uuid;
begin
  if not exists (
    select 1 from information_schema.columns
    where table_schema = 'supreme' and table_name = 'devices'
      and column_name = 'device_request_signing_key_sha256'
  ) or not exists (
    select 1 from information_schema.columns
    where table_schema = 'supreme' and table_name = 'devices'
      and column_name = 'device_request_signing_public_key_spki'
  ) then
    raise exception 'Request-signing device columns are missing';
  end if;

  if not exists (
    select 1 from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'supreme' and c.relname = 'api_request_challenges'
      and c.relkind = 'r' and c.relrowsecurity
  ) then
    raise exception 'Private challenge table or RLS is missing';
  end if;

  if has_table_privilege('anon', 'supreme.api_request_challenges', 'SELECT')
     or has_table_privilege('authenticated', 'supreme.api_request_challenges', 'SELECT') then
    raise exception 'A client/public role can read private request challenges';
  end if;

  if not has_table_privilege('service_role', 'supreme.api_request_challenges', 'SELECT')
     or not has_table_privilege('service_role', 'supreme.api_request_challenges', 'INSERT')
     or not has_table_privilege('service_role', 'supreme.api_request_challenges', 'UPDATE')
     or not has_table_privilege('service_role', 'supreme.api_request_challenges', 'DELETE') then
    raise exception 'Service role is missing required challenge-table privileges';
  end if;

  insert into auth.users(id) values (v_user_id);
  insert into supreme.devices(id, user_id) values (v_device_id, v_user_id);
  insert into supreme.app_sessions(id, user_id, device_id)
    values (v_session_id, v_user_id, v_device_id);

  insert into supreme.devices (
    id, user_id, device_request_signing_key_sha256,
    device_request_signing_public_key_spki
  ) values (
    gen_random_uuid(), v_user_id, repeat('a', 64), decode(repeat('ab', 64), 'hex')
  );

  insert into supreme.api_request_challenges (
    user_id, app_session_id, device_id, nonce_sha256, expires_at
  ) values (
    v_user_id, v_session_id, v_device_id, decode(repeat('cd', 32), 'hex'), now() + interval '60 seconds'
  ) returning id into v_challenge_id;

  if v_challenge_id is null then
    raise exception 'Challenge row could not be inserted';
  end if;

  begin
    insert into supreme.api_request_challenges (
      user_id, app_session_id, device_id, nonce_sha256, expires_at
    ) values (
      v_user_id, v_session_id, v_device_id, decode(repeat('ef', 31), 'hex'), now() + interval '60 seconds'
    );
    raise exception 'Invalid nonce length was accepted';
  exception when check_violation then
    null;
  end;
end;
$$;
