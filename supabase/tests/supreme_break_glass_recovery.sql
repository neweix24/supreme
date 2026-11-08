-- Break-glass recovery invariants. Run after all Supreme device/recovery migrations.
BEGIN;

DO $$
DECLARE
  v_user uuid := gen_random_uuid();
  v_auth_session uuid := gen_random_uuid();
  v_old_device uuid := gen_random_uuid();
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
BEGIN
  INSERT INTO auth.users(id) VALUES (v_user);
  -- Supabase sessions have no maximum lifetime by default; NULL not_after is valid.
  INSERT INTO auth.sessions(id, user_id, not_after)
  VALUES (v_auth_session, v_user, NULL);
  INSERT INTO supreme.identities(user_id, public_id, role, is_active)
  VALUES (v_user, 'supreme', 'ruler', true);

  -- Device history exists but no trusted device remains active.
  INSERT INTO supreme.devices(
    id, user_id, device_key_sha256, app_package, signing_certificate_sha256,
    security_level, attested_at, status, device_key_biometric_auth_required
  ) VALUES
    (v_old_device, v_user, repeat('b', 64), 'com.neweix.supreme',
     repeat('c', 64), 'strongbox', now() - interval '2 days', 'revoked', true),
    (v_pending_device, v_user, repeat('c', 64), 'com.neweix.supreme',
     repeat('d', 64), 'strongbox', now(), 'pending_approval', true);

  INSERT INTO supreme.device_enrollment_requests(id, user_id, device_id)
  VALUES (v_pending_enrollment, v_user, v_pending_device);

  v_hash := encode(digest(v_token, 'sha256'), 'hex');
  INSERT INTO supreme.recovery_authorizations(user_id, token_sha256, expires_at)
  VALUES (v_user, v_hash, now() + interval '30 days')
  RETURNING id INTO v_auth_id;

  PERFORM set_config('request.jwt.claim.role', 'service_role', true);
  v_result := public.begin_supreme_break_glass_recovery(v_user, v_auth_session, v_hash);
  v_request := (v_result ->> 'request_id')::uuid;
  v_available := (v_result ->> 'available_at')::timestamptz;
  IF v_request IS NULL OR v_available <= now() THEN
    RAISE EXCEPTION 'Recovery request did not enforce the 24-hour cooling-off period';
  END IF;

  -- Completion must be blocked until the independent notification is acknowledged.
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
    RAISE EXCEPTION 'Recovery completed before the cooling-off/notification gates';
  END IF;

  UPDATE supreme.recovery_requests
  SET requested_at = now() - interval '25 hours',
      available_at = now() - interval '1 hour',
      expires_at = now() + interval '6 days'
  WHERE id = v_request;

  -- Even after cooling-off, completion must be blocked until notification delivery.
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

  -- A successful independent delivery is acknowledged by the service role.
  PERFORM public.mark_supreme_recovery_notification_delivered(v_request, 'requested');

  BEGIN
    PERFORM public.complete_supreme_break_glass_recovery(
      v_user, v_auth_session, v_request, v_hash,
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
      v_user, v_auth_session, v_request, v_hash,
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
    v_user, v_auth_session, v_request, v_hash,
    repeat('d', 64), repeat('e', 64), 'strongbox',
    now(), now() + interval '4 hours'
  );
  IF v_result ->> 'completed' IS DISTINCT FROM 'true'
     OR v_result ->> 'registered' IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Break-glass recovery did not return a registered active session: %', v_result;
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
      v_user, v_auth_session, v_request, v_hash,
      repeat('f', 64), repeat('1', 64), 'strongbox',
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
