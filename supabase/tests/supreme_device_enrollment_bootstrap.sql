-- Bootstrap and pending-enrollment invariants. Run after the enrollment migration.
BEGIN;

DO $$
DECLARE
  v_user_id uuid := gen_random_uuid();
  v_first_auth_session uuid := gen_random_uuid();
  v_second_auth_session uuid := gen_random_uuid();
  v_result jsonb;
  v_first_device_id uuid;
  v_second_device_id uuid;
  v_status text;
BEGIN
  INSERT INTO auth.users(id) VALUES (v_user_id);
  INSERT INTO supreme.identities(user_id, public_id, role, is_active)
  VALUES (v_user_id, 'supreme', 'ruler', true);

  PERFORM set_config('request.jwt.claim.role', 'service_role', true);

  -- No device rows and no token: fail closed without creating a pending orphan.
  v_result := public.register_supreme_attested_device_session(
    v_user_id, v_first_auth_session, repeat('1', 64), repeat('a', 64),
    'strongbox', now(), now() + interval '4 hours', null
  );
  IF v_result ->> 'bootstrap_required' IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Missing bootstrap token did not fail closed: %', v_result;
  END IF;
  IF EXISTS (SELECT 1 FROM supreme.devices WHERE user_id = v_user_id) THEN
    RAISE EXCEPTION 'Missing bootstrap token created a device row';
  END IF;

  -- Wrong token must not create a device or consume the real authorization.
  INSERT INTO supreme.device_bootstrap_authorizations(user_id, token_sha256, expires_at)
  VALUES (v_user_id, repeat('b', 64), now() + interval '7 days');

  v_result := public.register_supreme_attested_device_session(
    v_user_id, v_first_auth_session, repeat('1', 64), repeat('a', 64),
    'strongbox', now(), now() + interval '4 hours', repeat('c', 64)
  );
  IF v_result ->> 'bootstrap_required' IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Wrong bootstrap token did not fail closed: %', v_result;
  END IF;
  IF EXISTS (SELECT 1 FROM supreme.devices WHERE user_id = v_user_id) THEN
    RAISE EXCEPTION 'Wrong bootstrap token created a device row';
  END IF;

  -- The exact one-time authorization bootstraps the only first device.
  v_result := public.register_supreme_attested_device_session(
    v_user_id, v_first_auth_session, repeat('1', 64), repeat('a', 64),
    'strongbox', now(), now() + interval '4 hours', repeat('b', 64)
  );
  IF v_result ->> 'bootstrap_completed' IS DISTINCT FROM 'true'
     OR v_result ->> 'pending_approval' IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'Valid first-device bootstrap failed: %', v_result;
  END IF;
  v_first_device_id := (v_result ->> 'device_id')::uuid;
  IF NOT EXISTS (
    SELECT 1 FROM supreme.app_sessions
    WHERE device_id = v_first_device_id
      AND auth_session_id = v_first_auth_session
      AND status = 'active'
  ) THEN
    RAISE EXCEPTION 'Bootstrap did not create the first active app session';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM supreme.device_bootstrap_authorizations
    WHERE user_id = v_user_id
      AND token_sha256 = repeat('b', 64)
      AND consumed_at IS NOT NULL
      AND consumed_device_id = v_first_device_id
  ) THEN
    RAISE EXCEPTION 'Bootstrap authorization was not atomically consumed';
  END IF;

  -- A second key is pending even if the consumed bootstrap token is replayed.
  v_result := public.register_supreme_attested_device_session(
    v_user_id, v_second_auth_session, repeat('2', 64), repeat('d', 64),
    'trusted_environment', now(), now() + interval '4 hours', repeat('b', 64)
  );
  IF v_result ->> 'pending_approval' IS DISTINCT FROM 'true'
     OR v_result ? 'session_id' THEN
    RAISE EXCEPTION 'Second device bypassed trusted-device approval: %', v_result;
  END IF;
  v_second_device_id := (v_result ->> 'device_id')::uuid;
  IF EXISTS (SELECT 1 FROM supreme.app_sessions WHERE device_id = v_second_device_id) THEN
    RAISE EXCEPTION 'Pending device received an app session';
  END IF;

  -- Historical device rows, including revoked, disqualify bootstrap for a new key.
  UPDATE supreme.devices SET status = 'revoked' WHERE id = v_first_device_id;
  v_result := public.register_supreme_attested_device_session(
    v_user_id, gen_random_uuid(), repeat('3', 64), repeat('e', 64),
    'strongbox', now(), now() + interval '4 hours', repeat('b', 64)
  );
  IF v_result ->> 'pending_approval' IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Device history did not disable bootstrap: %', v_result;
  END IF;

  -- Re-attestation must never reactivate the revoked key.
  BEGIN
    PERFORM public.register_supreme_attested_device_session(
      v_user_id, gen_random_uuid(), repeat('1', 64), repeat('a', 64),
      'strongbox', now(), now() + interval '4 hours', repeat('b', 64)
    );
    RAISE EXCEPTION 'Revoked device key was unexpectedly reactivated';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  SELECT status INTO v_status FROM supreme.devices WHERE id = v_first_device_id;
  IF v_status <> 'revoked' THEN
    RAISE EXCEPTION 'Revoked device status changed: %', v_status;
  END IF;

  UPDATE supreme.devices SET status = 'blocked' WHERE id = v_second_device_id;
  BEGIN
    PERFORM public.register_supreme_attested_device_session(
      v_user_id, gen_random_uuid(), repeat('2', 64), repeat('d', 64),
      'trusted_environment', now(), now() + interval '4 hours', repeat('b', 64)
    );
    RAISE EXCEPTION 'Blocked device key was unexpectedly reactivated';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  SELECT status INTO v_status FROM supreme.devices WHERE id = v_second_device_id;
  IF v_status <> 'blocked' THEN
    RAISE EXCEPTION 'Blocked device status changed: %', v_status;
  END IF;
END;
$$;

ROLLBACK;
