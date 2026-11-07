-- Supreme authorization must use supreme.identities, never the removed public.staff_profiles table.
-- The legacy helper name is retained for RPC compatibility, but it now recognizes
-- only the single active Supreme ruler identity. Employee roles are not inferred here.

create or replace function private.has_staff_role(required_roles text[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select coalesce(
    'supreme' = any(coalesce(required_roles, array[]::text[]))
    and exists (
      select 1
      from supreme.identities i
      where i.user_id = (select auth.uid())
        and i.public_id = 'supreme'
        and i.role = 'ruler'
        and i.is_active = true
    ),
    false
  );
$function$;

revoke all on function private.has_staff_role(text[]) from public, anon;
grant execute on function private.has_staff_role(text[]) to authenticated, service_role;

create or replace function public.is_current_supreme_ruler()
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select exists (
    select 1
    from supreme.identities i
    where i.user_id = (select auth.uid())
      and i.public_id = 'supreme'
      and i.role = 'ruler'
      and i.is_active = true
  );
$function$;

revoke all on function public.is_current_supreme_ruler() from public, anon;
grant execute on function public.is_current_supreme_ruler() to authenticated, service_role;

create or replace function public.eixpay_supreme_decide_product_review(
  p_review_id uuid,
  p_decision text,
  p_note text default ''
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_actor uuid := auth.uid();
  v_review private.eixpay_product_reviews%rowtype;
  v_reward jsonb;
  v_awarded bigint := 0;
  v_reward_reason text;
begin
  if v_actor is null then
    raise exception using errcode = '28000', message = 'AUTHENTICATION_REQUIRED';
  end if;

  if coalesce(auth.jwt() ->> 'aal', '') <> 'aal2' or not exists (
    select 1 from supreme.identities
    where user_id = v_actor and public_id = 'supreme'
      and role = 'ruler' and is_active = true
  ) then
    raise exception using errcode = '42501', message = 'SUPREME_MFA_REQUIRED';
  end if;

  if p_review_id is null or p_decision is null
     or p_decision not in ('approve', 'reject')
     or char_length(coalesce(p_note, '')) > 500 then
    raise exception using errcode = '22023', message = 'INVALID_REVIEW_DECISION';
  end if;

  select * into v_review
  from private.eixpay_product_reviews
  where id = p_review_id
  for update;

  if not found then
    raise exception using errcode = 'P0002', message = 'REVIEW_NOT_FOUND';
  end if;
  if v_review.status <> 'pending' then
    raise exception using errcode = '55000', message = 'REVIEW_ALREADY_DECIDED';
  end if;

  if p_decision = 'approve' then
    v_reward := private.eixpay_apply_reward(
      v_review.user_id, 'verified_review', v_review.id,
      'verified-review:' || v_review.id::text, null, v_actor
    );
    if coalesce((v_reward ->> 'success')::boolean, false) then
      v_awarded := coalesce((v_reward ->> 'awarded')::bigint, 0);
    else
      v_reward_reason := coalesce(v_reward ->> 'reason', 'reward_not_available');
    end if;
    update private.eixpay_product_reviews
    set status = 'approved', reward_awarded = v_awarded,
        moderation_note = coalesce(p_note, ''), decided_at = now(),
        decided_by = v_actor, updated_at = now()
    where id = p_review_id;
  else
    update private.eixpay_product_reviews
    set status = 'rejected', moderation_note = coalesce(p_note, ''),
        decided_at = now(), decided_by = v_actor, updated_at = now()
    where id = p_review_id;
  end if;

  insert into private.eixpay_audit_events(actor_id, event_code, subject_id, metadata)
  values (v_actor, 'product_review_' || p_decision, p_review_id,
    jsonb_build_object(
      'user_id', v_review.user_id, 'product_id', v_review.product_id,
      'rating', v_review.rating, 'reward_awarded', v_awarded,
      'reward_unavailable_reason', v_reward_reason
    ));

  return jsonb_build_object(
    'success', true,
    'status', case when p_decision = 'approve' then 'approved' else 'rejected' end,
    'reward_awarded', v_awarded,
    'reward_unavailable_reason', v_reward_reason
  );
end;
$function$;

revoke all on function public.eixpay_supreme_decide_product_review(uuid, text, text) from public, anon;
grant execute on function public.eixpay_supreme_decide_product_review(uuid, text, text) to authenticated, service_role;

create or replace function public.eixpay_supreme_list_product_reviews()
returns table(
  review_id uuid, product_id uuid, product_name text, order_number text,
  reviewer_name text, reviewer_user_id uuid, rating smallint,
  title text, body text, created_at timestamptz
)
language plpgsql
stable
security definer
set search_path = ''
as $function$
declare
  v_actor uuid := auth.uid();
begin
  if v_actor is null then
    raise exception using errcode = '28000', message = 'AUTHENTICATION_REQUIRED';
  end if;

  if coalesce(auth.jwt() ->> 'aal', '') <> 'aal2' or not exists (
    select 1 from supreme.identities
    where user_id = v_actor and public_id = 'supreme'
      and role = 'ruler' and is_active = true
  ) then
    raise exception using errcode = '42501', message = 'SUPREME_MFA_REQUIRED';
  end if;

  return query
  select r.id, r.product_id, p.name, o.order_number,
    coalesce(nullif(cp.display_name, ''), nullif(cp.full_name, ''), 'NEWEIX ক্রেতা'),
    r.user_id, r.rating, r.title, r.body, r.created_at
  from private.eixpay_product_reviews r
  join public.products p on p.id = r.product_id
  join public.orders o on o.id = r.order_id
  left join public.customer_profiles cp on cp.user_id = r.user_id
  where r.status = 'pending'
  order by r.created_at asc
  limit 100;
end;
$function$;

revoke all on function public.eixpay_supreme_list_product_reviews() from public, anon;
grant execute on function public.eixpay_supreme_list_product_reviews() to authenticated, service_role;
