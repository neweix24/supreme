-- Reconcile the Supreme registry with the canonical nine-repository ecosystem charter.
-- This migration is intentionally source-only until its live preconditions are reviewed and Supreme approves production application.

insert into supreme.services (
  service_id, display_name, description,
  repository_provider, repository_full_name, repository_default_branch, repository_url,
  owner_team, data_classification, risk_tier, status,
  health_check_kind, health_check_path, health_check_timeout_seconds,
  health_check_expected_status, metadata_version
) values
  ('supreme', 'Supreme', 'Highest ecosystem authority: policy, delegated authority, reserved approvals, oversight, and protected control-plane security.', 'github', 'neweix24/supreme', 'main', 'https://github.com/neweix24/supreme', 'Supreme', 'restricted', 'critical', 'active', 'none', null, 5, array[200], 2),
  ('neweix', 'Neweix', 'Public ecosystem website, central service directory, and Admin workspace entry point. Service-owned data remains outside Neweix.', 'github', 'neweix24/neweix', 'main', 'https://github.com/neweix24/neweix', 'Neweix', 'public', 'high', 'active', 'none', null, 5, array[200], 2),
  ('neweix-account', 'Neweix Account', 'Customer identity, credentials, Account IDs, customer profiles, recovery, and customer sessions. Not the Admin or Supreme identity provider.', 'github', 'neweix24/account', 'main', 'https://github.com/neweix24/account', 'Neweix Account', 'restricted', 'critical', 'active', 'none', null, 5, array[200], 2),
  ('employees', 'Employees', 'Admin and workforce identity records, employee records, job roles, and delegated workforce permissions.', 'github', 'neweix24/employees', 'main', 'https://github.com/neweix24/employees', 'Employees', 'restricted', 'high', 'planned', 'none', null, 5, array[200], 1),
  ('eixon', 'Eixon', 'EIX token, wallet and unit ledger for eligible Neweix purchases and the designated gift workflow. Ordinary P2P and external transfers are prohibited.', 'github', 'neweix24/eixon', 'main', 'https://github.com/neweix24/eixon', 'Eixon', 'restricted', 'critical', 'planned', 'none', null, 5, array[200], 2),
  ('neweix-shop', 'Neweix Shop', 'Neweix single-vendor commerce: catalogue, cart, orders, inventory, fulfilment, returns, and shop support. Storefront is deployed; API and checkout remain gated.', 'github', 'neweix24/shop', 'main', 'https://github.com/neweix24/shop', 'Neweix Shop', 'confidential', 'high', 'active', 'none', null, 5, array[200], 2),
  ('neweix-connect', 'Neweix Connect', 'Private conversations, groups, messages, attachments, notifications, and communication abuse controls.', 'github', 'neweix24/connect', 'main', 'https://github.com/neweix24/connect', 'Neweix Connect', 'confidential', 'high', 'planned', 'none', null, 5, array[200], 1),
  ('neweix-plus', 'Neweix+', 'Separate subscription plans, billing periods, membership state, and entitlements. Eixon owns payment/ledger processing.', 'github', 'neweix24/neweix-plus', 'main', 'https://github.com/neweix24/neweix-plus', 'Neweix+', 'confidential', 'moderate', 'planned', 'none', null, 5, array[200], 1),
  ('eixora', 'Eixora', 'Social profiles, posts, feeds, comments, reactions, follows, discovery, and moderation.', 'github', 'neweix24/eixora', 'main', 'https://github.com/neweix24/eixora', 'Eixora', 'confidential', 'high', 'planned', 'none', null, 5, array[200], 1)
on conflict (service_id) do update set
  display_name = excluded.display_name,
  description = excluded.description,
  repository_provider = excluded.repository_provider,
  repository_full_name = excluded.repository_full_name,
  repository_default_branch = excluded.repository_default_branch,
  repository_url = excluded.repository_url,
  owner_team = excluded.owner_team,
  data_classification = excluded.data_classification,
  risk_tier = excluded.risk_tier,
  status = excluded.status,
  health_check_kind = excluded.health_check_kind,
  health_check_path = excluded.health_check_path,
  health_check_timeout_seconds = excluded.health_check_timeout_seconds,
  health_check_expected_status = excluded.health_check_expected_status,
  metadata_version = supreme.services.metadata_version + 1,
  updated_at = now();

-- Keep the old registry identifier for audit/history, but make it non-operational.
update supreme.services
set display_name = 'Neweix Message (retired alias)',
    description = 'Retired legacy registry alias. The current communication service is neweix-connect; this record must not be used for routing or authorization.',
    repository_provider = 'github',
    repository_full_name = 'neweix24/connect',
    repository_default_branch = 'main',
    repository_url = 'https://github.com/neweix24/connect',
    owner_team = 'Supreme Registry',
    status = 'retired',
    metadata_version = metadata_version + 1,
    updated_at = now()
where service_id = 'neweix-message';

-- Production endpoints are enabled only for existing, documented production hosts.
insert into supreme.service_environments (service_id, environment_id, classification, api_base_url, enabled)
values
  ('neweix', 'production', 'production', 'https://www.neweix.com', true),
  ('neweix-account', 'production', 'production', 'https://www.accounts.neweix.com', true),
  ('neweix-shop', 'production', 'production', 'https://www.shop.neweix.com', true),
  ('supreme', 'production', 'production', null, false),
  ('employees', 'development', 'development', null, false),
  ('eixon', 'development', 'development', null, false),
  ('neweix-connect', 'development', 'development', null, false),
  ('neweix-plus', 'development', 'development', null, false),
  ('eixora', 'development', 'development', null, false)
on conflict (service_id, environment_id) do update set
  classification = excluded.classification,
  api_base_url = excluded.api_base_url,
  enabled = excluded.enabled,
  updated_at = now();

update supreme.service_environments
set enabled = false, updated_at = now()
where service_id = 'neweix-message';

-- No service capabilities or provider secrets are granted by this inventory migration.
