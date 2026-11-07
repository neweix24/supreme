-- Run with: supabase test db
begin;

do $test$
declare
  v_supreme_user uuid;
  v_other_user uuid := '00000000-0000-4000-8000-000000000001'::uuid;
begin
  select user_id into v_supreme_user
  from supreme.identities
  where public_id = 'supreme' and role = 'ruler' and is_active = true
  limit 1;

  if v_supreme_user is null then
    raise exception 'ACTIVE_SUPREME_RULER_IDENTITY_MISSING';
  end if;

  perform set_config('request.jwt.claim.sub', v_supreme_user::text, true);
  perform set_config('request.jwt.claims',
    jsonb_build_object('sub', v_supreme_user, 'role', 'authenticated', 'aal', 'aal2')::text, true);

  if public.is_current_supreme_ruler() is not true then
    raise exception 'SUPREME_IDENTITY_CHECK_REJECTED_ACTIVE_RULER';
  end if;
  if private.has_staff_role(array['supreme']::text[]) is not true then
    raise exception 'LEGACY_ROLE_HELPER_REJECTED_ACTIVE_RULER';
  end if;
  if private.has_staff_role(array['supreme', 'admin']::text[]) is not true then
    raise exception 'LEGACY_ROLE_HELPER_REJECTED_SUPREME_ALLOWED_ROLE';
  end if;
  if private.has_staff_role(array['admin']::text[]) is not false then
    raise exception 'SUPREME_IDENTITY_MUST_NOT_IMPLY_ADMIN_EMPLOYEE_ROLE';
  end if;

  perform set_config('request.jwt.claim.sub', v_other_user::text, true);
  perform set_config('request.jwt.claims',
    jsonb_build_object('sub', v_other_user, 'role', 'authenticated', 'aal', 'aal2')::text, true);

  if public.is_current_supreme_ruler() is not false then
    raise exception 'NON_SUPREME_USER_RECEIVED_SUPREME_IDENTITY';
  end if;
  if private.has_staff_role(array['supreme']::text[]) is not false then
    raise exception 'NON_SUPREME_USER_RECEIVED_SUPREME_ROLE';
  end if;
end;
$test$;

rollback;
