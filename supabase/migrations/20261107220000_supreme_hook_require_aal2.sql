-- Only issue the device-bound Supreme claim on an AAL2 access token.
-- Keep the database row check as the source of truth on every token refresh.
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
begin
  claims := coalesce(event -> 'claims', '{}'::jsonb);

  if coalesce(claims ->> 'aal', '') <> 'aal2' then
    claims := claims - 'supreme_app_session';
    return jsonb_set(event, '{claims}', claims, true);
  end if;

  if coalesce(event ->> 'user_id', '') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    claims := claims - 'supreme_app_session';
    return jsonb_set(event, '{claims}', claims, true);
  end if;
  event_user_id := (event ->> 'user_id')::uuid;

  if coalesce(claims ->> 'session_id', '') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    claims := claims - 'supreme_app_session';
    return jsonb_set(event, '{claims}', claims, true);
  end if;
  event_session_id := (claims ->> 'session_id')::uuid;

  if not exists (
    select 1
    from supreme.identities i
    where i.user_id = event_user_id
      and i.public_id = 'supreme'
      and i.role = 'ruler'
      and i.is_active = true
  ) then
    claims := claims - 'supreme_app_session';
    return jsonb_set(event, '{claims}', claims, true);
  end if;

  select
    s.id as session_id,
    s.device_id,
    extract(epoch from d.attested_at)::bigint as attested_at
  into session_row
  from supreme.app_sessions s
  join supreme.devices d on d.id = s.device_id
  where s.user_id = event_user_id
    and s.auth_session_id = event_session_id
    and s.status = 'active'
    and s.expires_at > now()
    and d.user_id = event_user_id
    and d.status = 'active'
    and d.app_package = 'com.neweix.supreme'
    and d.security_level in ('trusted_environment', 'strongbox')
    and d.attested_at <= now()
    and d.attested_at > now() - interval '30 days'
  limit 1;

  if session_row.session_id is null then
    claims := claims - 'supreme_app_session';
  else
    claims := jsonb_set(
      claims,
      '{supreme_app_session}',
      jsonb_build_object(
        'status', 'active',
        'session_id', session_row.session_id,
        'device_id', session_row.device_id,
        'attested_at', session_row.attested_at
      ),
      true
    );
  end if;

  return jsonb_set(event, '{claims}', claims, true);
end;
$$;

revoke all on function public.supreme_custom_access_token_hook(jsonb)
  from public, anon, authenticated;
grant usage on schema supreme to supabase_auth_admin;
grant select on supreme.identities, supreme.devices, supreme.app_sessions
  to supabase_auth_admin;
grant execute on function public.supreme_custom_access_token_hook(jsonb)
  to supabase_auth_admin;
