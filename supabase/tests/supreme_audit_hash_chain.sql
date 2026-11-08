-- Run after applying the Supreme migrations in a disposable test database.
begin;

insert into supreme.audit_events (
  request_id, actor_user_id, action, outcome, policy_version, details
) values
  (gen_random_uuid(), null, 'test.hash_chain.one', 'success', 'test', jsonb_build_object('case', 1)),
  (gen_random_uuid(), null, 'test.hash_chain.two', 'success', 'test', jsonb_build_object('case', 2)),
  (gen_random_uuid(), null, 'test.hash_chain.three', 'success', 'test', jsonb_build_object('case', 3));

do $$
declare
  v_count integer;
begin
  if supreme.verify_audit_event_hash_chain() is distinct from true then
    raise exception 'Supreme audit hash-chain verification failed after inserts';
  end if;

  select count(*) into v_count
    from supreme.audit_events
   where action like 'test.hash_chain.%';

  if v_count <> 3 then
    raise exception 'Expected three test audit events, found %', v_count;
  end if;

  begin
    update supreme.audit_events
       set details = jsonb_build_object('tampered', true)
     where action = 'test.hash_chain.one';
    raise exception 'Audit update unexpectedly succeeded';
  exception
    when others then
      if sqlerrm = 'Audit update unexpectedly succeeded' then
        raise;
      end if;
  end;

  begin
    delete from supreme.audit_events
     where action = 'test.hash_chain.two';
    raise exception 'Audit delete unexpectedly succeeded';
  exception
    when others then
      if sqlerrm = 'Audit delete unexpectedly succeeded' then
        raise;
      end if;
  end;

  if supreme.verify_audit_event_hash_chain() is distinct from true then
    raise exception 'Supreme audit hash-chain verification failed after rejected mutations';
  end if;

  -- Simulate a privileged/operator-level tamper that bypasses the row trigger.
  alter table supreme.audit_events disable trigger supreme_audit_events_immutable;
  update supreme.audit_events
     set details = jsonb_build_object('tampered', true)
   where action = 'test.hash_chain.two';
  alter table supreme.audit_events enable trigger supreme_audit_events_immutable;

  if supreme.verify_audit_event_hash_chain() is distinct from false then
    raise exception 'Hash-chain verifier did not detect a privileged audit-event modification';
  end if;
end;
$;

rollback;
