-- Cryptographically link Supreme audit events into one append-only chain.
-- The advisory lock serializes inserts so concurrent writers cannot fork the chain.
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

alter table supreme.audit_events
  add column if not exists chain_position bigint,
  add column if not exists previous_hash bytea,
  add column if not exists event_hash bytea;

-- Temporarily remove the row mutation guard only inside this migration so the
-- existing history can be backfilled in stable identity order.
drop trigger if exists supreme_audit_events_immutable on supreme.audit_events;

do $$
declare
  v_event record;
  v_previous_hash bytea := null;
  v_position bigint := 0;
  v_payload jsonb;
  v_event_hash bytea;
begin
  perform set_config('search_path', 'pg_catalog, supreme, extensions, public', true);
  perform pg_advisory_xact_lock(731904221);

  for v_event in
    select * from supreme.audit_events order by id asc
  loop
    v_position := v_position + 1;
    v_payload := to_jsonb(v_event) - 'chain_position' - 'previous_hash' - 'event_hash';
    v_event_hash := digest(
      convert_to(coalesce(encode(v_previous_hash, 'hex'), '') || E'\\n' || v_payload::text, 'UTF8'),
      'sha256'
    );

    update supreme.audit_events
       set chain_position = v_position,
           previous_hash = v_previous_hash,
           event_hash = v_event_hash
     where id = v_event.id;

    v_previous_hash := v_event_hash;
  end loop;
end;
$$;

alter table supreme.audit_events
  alter column chain_position set not null,
  add constraint supreme_audit_chain_position_unique unique (chain_position),
  alter column event_hash set not null,
  add constraint supreme_audit_previous_hash_size
    check (previous_hash is null or octet_length(previous_hash) = 32),
  add constraint supreme_audit_event_hash_size
    check (octet_length(event_hash) = 32);

create index if not exists supreme_audit_events_hash_idx
  on supreme.audit_events (event_hash);

create or replace function supreme.append_audit_event_hash()
returns trigger
language plpgsql
set search_path = pg_catalog, supreme, extensions, public
as $$
declare
  v_previous_hash bytea;
  v_payload jsonb;
begin
  perform pg_advisory_xact_lock(731904221);

  select coalesce(max(chain_position), 0) + 1
    into new.chain_position
    from supreme.audit_events;

  select event_hash
    into v_previous_hash
    from supreme.audit_events
   order by chain_position desc
   limit 1;

  new.previous_hash := v_previous_hash;
  v_payload := to_jsonb(new) - 'chain_position' - 'previous_hash' - 'event_hash';
  new.event_hash := digest(
    convert_to(coalesce(encode(v_previous_hash, 'hex'), '') || E'\\n' || v_payload::text, 'UTF8'),
    'sha256'
  );

  return new;
end;
$$;

revoke all on function supreme.append_audit_event_hash() from public, anon, authenticated;
drop trigger if exists supreme_audit_events_hash_chain_insert on supreme.audit_events;
create trigger supreme_audit_events_hash_chain_insert
before insert on supreme.audit_events
for each row execute function supreme.append_audit_event_hash();

create or replace function supreme.verify_audit_event_hash_chain()
returns boolean
language plpgsql
stable
security invoker
set search_path = pg_catalog, supreme, extensions, public
as $$
declare
  v_event record;
  v_previous_hash bytea := null;
  v_expected_hash bytea;
  v_payload jsonb;
begin
  for v_event in
    select * from supreme.audit_events order by chain_position asc
  loop
    if v_event.previous_hash is distinct from v_previous_hash then
      return false;
    end if;

    v_payload := to_jsonb(v_event) - 'chain_position' - 'previous_hash' - 'event_hash';
    v_expected_hash := digest(
      convert_to(coalesce(encode(v_previous_hash, 'hex'), '') || E'\\n' || v_payload::text, 'UTF8'),
      'sha256'
    );

    if v_event.event_hash is distinct from v_expected_hash then
      return false;
    end if;

    v_previous_hash := v_event.event_hash;
  end loop;

  return true;
end;
$$;

revoke all on function supreme.verify_audit_event_hash_chain() from public, anon, authenticated;
grant execute on function supreme.verify_audit_event_hash_chain() to service_role;

create trigger supreme_audit_events_immutable
before update or delete on supreme.audit_events
for each row execute function supreme.reject_audit_mutation();

comment on column supreme.audit_events.chain_position is
  'Monotonic insertion order assigned under the audit-chain advisory lock; independent of preallocated identity values.';
comment on column supreme.audit_events.previous_hash is
  'SHA-256 hash of the preceding audit event; NULL only for the first event.';
comment on column supreme.audit_events.event_hash is
  'SHA-256 hash of the canonical event payload linked to previous_hash. Detects edits, deletion, and reordering when the chain is verified.';
comment on function supreme.verify_audit_event_hash_chain() is
  'Returns false if any Supreme audit event payload, ordering link, or stored event hash differs from the append-only SHA-256 chain.';
