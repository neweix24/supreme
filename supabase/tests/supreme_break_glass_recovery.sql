-- Break-glass recovery invariants. Run after all Supreme device/recovery migrations.
BEGIN;

DO $$
DECLARE
  v_user uuid := gen_random_uuid();
  v_auth_session uuid := gen_random_uuid();
  v_old_auth_session uuid := gen_random_uuid();
  v_completion_auth_session uuid := gen_random_uuid();
  v_expired_auth_session uuid := gen_random_uuid();
  v_old_device uuid := gen_random_uuid();
  v_active_device uuid := gen_random_uuid();
  v_old_app_session uuid := gen_random_uuid();
  v_pending_device uuid := gen_random_uuid();
  v_pending_enrollment uuid := gen_random_uuid();
  v_request uuid;
  v_auth_id uuid;
  v_token text := repeat('a7', 32);
  v_hash text;
  v_result jsonb;
  v_available timestamptz;
  v_status text;
  v_device_status text;
  v_session_status text;
  v_replay_rejected boolean := false;
  v_early_rejected boolean := false;
  v_null_security_rejected boolean := false;
  v_null_expiry_rejected boolean := false;
  v_expired_session_rejected boolean := false;
  v_active_device_rejected boolean := false;
BEGIN
  INSERT INTO auth.users(id) VALUES (v_user);

  -- Supabase sessions have no maximum lifetime by default; NULL not_after is valid.
  INSERT INTO auth.sessions(id, user_id, not_after)
  VALUES
    (v_auth_session, v_user, NULL),
    (v_old_auth_session, v_user, NULL),
    (v_expired_auth_session, v_user, now() - interval '1 minute');

  INSERT INTO supreme.identities(user_id, public_id, role, is_active)
  VALUES (v_user, 'supreme', 'ruler', true);

  -- Device history exists, but no trusted device remains active after the
  -- active-device precondition is checked below.
  INSERT INTO supreme.devices(
    id, user_id, device_key_sha256, app_package, signing_certificate_sha256,
    security_level, attested_at, status, device_key_biometric_auth_required
  ) VALUES
    (v_old_device, v_user, repeat('b', 64), 'com.neweix.supreme',
     repeat('c', 64), 'strongbox', now() - interval '2 days', 'revoked', true),
    (v_active_device, v_user, repeat('f', 64), 'com.neweix.supreme',
     repeat('1', 64), 'strongbox', now(), 'active', true),
    (v_pending_device, v_user, repeat('c', 64), 'com.neweix.supreme',
     repeat('d', 64), 'strongbox', now(), 'pending_approval', true);

  INSERT INTO supreme.device_enrollment_requests(id, user_id, device_id)
  VALUES (v_pending_enrollment, v_user, v_pending_device);

  INSERT INTO supreme.app_sessions(
    id, user_id, device_id, auth_session_id, status,
    attested_at, expires_at, created_at, updated_at
  ) VALUES (
    v_old_app_session, v_user, v_old_device, v_old_auth_session, 'active',
    now() - interval '1 day', now() + interval '1 hour', now(), now()
  );

  v_hash := encode(digest(v_token, 'sha256'), 'hex');
  INSERT INTO supreme.recovery_authorizations(user_id, token_sha256, expires_at)
  VALUES (v_user, v_hash, now() + interval '30 days')
  RETURNING id INTO v_auth_id;

  PERFORM set_config('request.jwt.claim.role', 'service_role', true);

  -- A session whose explicit not_after is in the past must be rejected.
  BEGIN
    PERFORM public.begin_supreme_break_glass_recovery(
      v_user, v_expired_auth_session, v_hash
    );
  EXCEPTION WHEN SQLSTATE '42501' THEN
    v_expired_session_rejected := true;
  END;
  IF NOT v_expired_session_rejected THEN
    RAISE EXCEPTION 'Recovery accepted an Auth session whose not_after is in the past';
  END IF;

  -- Recovery is unavailable while any trusted device remains active.
  BEGIN
    PERFORM public.begin_supreme_break_glass_recovery(
      v_user, v_auth_session, v_hash
    );
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    v_active_device_rejected := true;
  END;
  IF NOT v_active_device_rejected THEN
    RAISE EXCEPTION 'Recovery started while an active trusted device existed';
  END IF;

  UPDATE supreme.devices SET status = 'revoked', updated_at = now()
  WHERE id = v_active_device;

  v_result := public.begin_supreme_break_glass_recovery(
    v_user, v_auth_session, v_hash
  );
  v_request := (v_result ->> 'request_id')::uuid;
  v_available := (v_result ->> 'available_at')::timestamptz;
  IF v_request IS NULL OR v_available <= now() THEN
    RAISE EXCEPTION 'Recovery request did not enforce the 24-hour cooling-off period';
  END IF;

  -- Keep only the fresh request session; revoke all previous Auth sessions.
  IF NOT EXISTS (SELECT 1 FROM auth.sessions WHERE id = v_auth_session)
     OR EXISTS (
       SELECT 1 FROM auth.sessions
       WHERE id IN (v_old_auth_session, v_expired_auth_session)
     ) THEN
    RAISE EXCEPTION 'Recovery request did not retain only its fresh Auth session';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM supreme.app_sessions
    WHERE id = v_old_app_session AND status = 'revoked' AND revoked_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'Recovery request did not immediately revoke old device app sessions';
  END IF;

  -- Completion must be blocked during the cooling-off period.
  BEGIN
    PERFORM public.complete_supreme_break_glass_recovery(
      v_user, v_auth_session, v_request, v_hash,
      repeat('d', 64), repeat('e', 64), 'strongbox',
      now(), now() + interval '4 hours'
    );
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    v_early_rejected := true;
  END;
  IF NOT v_early_rejected THEN
    RAISE EXCEPTION 'Recovery completed before the 24-hour cooling-off period';
  END IF;

  -- Simulate the passage of the cooling-off period.
  UPDATE supreme.recovery_requests
  SET requested_at = now() - interval '25 hours',
      available_at = now() - interval '1 hour',
      expires_at = now() + interval '6 days'
  WHERE id = v_request;

  -- Even after cooling-off, completion is blocked until independent notification.
  v_early_rejected := false;
  BEGIN
    PERFORM public.complete_supreme_break_glass_recovery(
      v_user, v_auth_session, v_request, v_hash,
      repeat('d', 64), repeat('e', 64), 'strongbox',
      now(), now() + interval '4 hours'
    );
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    v_early_rejected := true;
  END;
  IF NOT v_early_rejected THEN
    RAISE EXCEPTION 'Recovery completed without independent notification delivery';
  END IF;

  PERFORM public.mark_supreme_recovery_notification_delivered(v_request, 'requested');

  -- A fresh Auth session is established after the cooling-off period.
  INSERT INTO auth.sessions(id, user_id, not_after)
  VALUES (v_completion_auth_session, v_user, NULL);

  -- NULL security level and NULL session expiry must be rejected.
  BEGIN
    PERFORM public.complete_supreme_break_glass_recovery(
      v_user, v_completion_auth_session, v_request, v_hash,
      repeat('d', 64), repeat('e', 64), NULL,
      now(), now() + interval '4 hours'
    );
  EXCEPTION WHEN SQLSTATE '22023' THEN
    v_null_security_rejected := true;
  END;
  IF NOT v_null_security_rejected THEN
    RAISE EXCEPTION 'Recovery accepted a NULL attestation security level';
  END IF;

  BEGIN
    PERFORM public.complete_supreme_break_glass_recovery(
      v_user, v_completion_auth_session, v_request, v_hash,
      repeat('d', 64), repeat('e', 64), 'strongbox',
      now(), NULL
    );
  EXCEPTION WHEN SQLSTATE '22023' THEN
    v_null_expiry_rejected := true;
  END;
  IF NOT v_null_expiry_rejected THEN
    RAISE EXCEPTION 'Recovery accepted a NULL app-session expiry';
  END IF;

  v_result := public.complete_supreme_break_glass_recovery(
    v_user, v_completion_auth_session, v_request, v_hash,
    repeat('d', 64), repeat('e', 64), 'strongbox',
    now(), now() + interval '4 hours'
  );
  IF v_result ->> 'completed' IS DISTINCT FROM 'true'
     OR v_result ->> 'registered' IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Break-glass recovery did not register the new device/session: %', v_result;
  END IF;

  SELECT status INTO v_status
  FROM supreme.recovery_requests WHERE id = v_request;
  IF v_status <> 'completed' THEN
    RAISE EXCEPTION 'Recovery request was not marked completed';
  END IF;

  SELECT status INTO v_device_status
  FROM supreme.devices WHERE id = (v_result ->> 'device_id')::uuid;
  IF v_device_status <> 'active' THEN
    RAISE EXCEPTION 'Replacement device is not active';
  END IF;

  SELECT status INTO v_session_status
  FROM supreme.app_sessions WHERE id = (v_result ->> 'session_id')::uuid;
  IF v_session_status <> 'active' THEN
    RAISE EXCEPTION 'Replacement device session is not active';
  END IF;

  -- Only the fresh completion Auth session survives.
  IF NOT EXISTS (SELECT 1 FROM auth.sessions WHERE id = v_completion_auth_session)
     OR EXISTS (
       SELECT 1 FROM auth.sessions
       WHERE id IN (v_auth_session, v_old_auth_session, v_expired_auth_session)
     ) THEN
    RAISE EXCEPTION 'Recovery completion did not retain only its fresh Auth session';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM supreme.recovery_authorizations
    WHERE id = v_auth_id AND consumed_at IS NOT NULL
      AND consumed_by_request_id = v_request
  ) THEN
    RAISE EXCEPTION 'Offline recovery material was not consumed atomically';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM supreme.devices
    WHERE id = v_old_device AND status = 'revoked'
  ) THEN
    RAISE EXCEPTION 'Previously revoked device was reactivated';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM supreme.devices
    WHERE id = v_pending_device AND status = 'revoked'
  ) OR NOT EXISTS (
    SELECT 1 FROM supreme.device_enrollment_requests
    WHERE id = v_pending_enrollment AND status = 'rejected'
  ) THEN
    RAISE EXCEPTION 'Recovery did not invalidate pending device enrollment';
  END IF;

  -- A completed request and consumed offline material cannot be replayed.
  BEGIN
    PERFORM public.complete_supreme_break_glass_recovery(
      v_user, v_completion_auth_session, v_request, v_hash,
      repeat('1', 64), repeat('2', 64), 'strongbox',
      now(), now() + interval '4 hours'
    );
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    v_replay_rejected := true;
  END;
  IF NOT v_replay_rejected THEN
    RAISE EXCEPTION 'Completed recovery request was replayed';
  END IF;
END;
$$;

ROLLBACK;
