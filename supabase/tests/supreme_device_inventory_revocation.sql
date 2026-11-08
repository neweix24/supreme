-- Remote device revocation invariants. Run after both device-enrollment and inventory migrations.
BEGIN;

DO $$
DECLARE
  v_user_id uuid := gen_random_uuid();
  v_approver_device uuid := gen_random_uuid();
  v_target_device uuid := gen_random_uuid();
  v_approver_session uuid := gen_random_uuid();
  v_target_session uuid := gen_random_uuid();
  v_challenge uuid := gen_random_uuid();
  v_nonce bytea := decode(repeat('ab', 32), 'hex');
  v_result jsonb;
  v_status text;
  v_session_status text;
  v_consumed timestamptz;
BEGIN
  INSERT INTO auth.users(id) VALUES (v_user_id);
  INSERT INTO supreme.identities(user_id, public_id, role, is_active)
  VALUES (v_user_id, 'supreme', 'ruler', true);

  INSERT INTO supreme.devices(
    id, user_id, device_key_sha256, app_package, signing_certificate_sha256,
    security_level, attested_at, status, device_public_key_spki,
    device_key_biometric_auth_required
  ) VALUES
    (v_approver_device, v_user_id, repeat('a', 64), 'com.neweix.supreme',
     repeat('c', 64), 'strongbox', now(), 'active', decode(repeat('11', 65), 'hex'), true),
    (v_target_device, v_user_id, repeat('b', 64), 'com.neweix.supreme',
     repeat('c', 64), 'strongbox', now(), 'active', decode(repeat('22', 65), 'hex'), true);

  INSERT INTO supreme.app_sessions(
    user_id, device_id, auth_session_id, status, attested_at, expires_at
  ) VALUES
    (v_user_id, v_approver_device, v_approver_session, 'active', now(), now() + interval '4 hours'),
    (v_user_id, v_target_device, v_target_session, 'active', now(), now() + interval '4 hours');

  INSERT INTO supreme.device_management_challenges(
    id, user_id, action, target_device_id, approving_device_id,
    approving_auth_session_id, nonce_sha256, expires_at
  ) VALUES (
    v_challenge, v_user_id, 'revoke_device', v_target_device,
    v_approver_device, v_approver_session, v_nonce, now() + interval '90 seconds'
  );

  PERFORM set_config('request.jwt.claim.role', 'service_role', true);

  -- A trusted, different device can revoke the target and every active session atomically.
  v_result := public.revoke_supreme_device(
    v_user_id, v_target_device, v_challenge, v_approver_device,
    v_approver_session, v_nonce
  );
  IF v_result ->> 'revoked' IS DISTINCT FROM 'true'
     OR (v_result ->> 'revoked_sessions')::integer <> 1 THEN
    RAISE EXCEPTION 'Remote device revocation returned unexpected result: %', v_result;
  END IF;
  SELECT status INTO v_status FROM supreme.devices WHERE id = v_target_device;
  IF v_status <> 'revoked' THEN
    RAISE EXCEPTION 'Target device status is not revoked: %', v_status;
  END IF;
  SELECT status INTO v_session_status FROM supreme.app_sessions WHERE auth_session_id = v_target_session;
  IF v_session_status <> 'revoked' THEN
    RAISE EXCEPTION 'Target device app session is not revoked: %', v_session_status;
  END IF;
  SELECT consumed_at INTO v_consumed FROM supreme.device_management_challenges WHERE id = v_challenge;
  IF v_consumed IS NULL THEN
    RAISE EXCEPTION 'Device revocation challenge was not consumed';
  END IF;

  -- Replaying the same challenge must fail closed.
  BEGIN
    PERFORM public.revoke_supreme_device(
      v_user_id, v_target_device, v_challenge, v_approver_device,
      v_approver_session, v_nonce
    );
    RAISE EXCEPTION 'Consumed device revocation challenge was replayed';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    NULL;
  END;

  -- A device cannot revoke itself through the remote-management RPC.
  BEGIN
    PERFORM public.revoke_supreme_device(
      v_user_id, v_approver_device, gen_random_uuid(), v_approver_device,
      v_approver_session, v_nonce
    );
    RAISE EXCEPTION 'Self-revocation through remote-device RPC was accepted';
  EXCEPTION WHEN SQLSTATE '22023' THEN
    NULL;
  END;

  -- The approving device and its session remain active.
  SELECT status INTO v_status FROM supreme.devices WHERE id = v_approver_device;
  SELECT status INTO v_session_status FROM supreme.app_sessions WHERE auth_session_id = v_approver_session;
  IF v_status <> 'active' OR v_session_status <> 'active' THEN
    RAISE EXCEPTION 'Approving device or session was unexpectedly revoked';
  END IF;
END;
$$;

ROLLBACK;
