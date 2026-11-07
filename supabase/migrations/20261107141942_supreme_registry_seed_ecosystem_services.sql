-- Bootstrap the known Neweix ecosystem services without enabling unimplemented operations.
insert into supreme.services (
  service_id, display_name, description,
  repository_provider, repository_full_name, repository_default_branch, repository_url,
  owner_team, data_classification, risk_tier, status,
  health_check_kind, health_check_path, health_check_timeout_seconds,
  health_check_expected_status, metadata_version
) values
(
  'neweix', 'Neweix', 'Production Neweix website and legacy application host. The repository README documents the existing storefront, customer, order, payment and delivery operations.',
  'github', 'neweix24/neweix', 'main', 'https://github.com/neweix24/neweix',
  'Neweix', 'confidential', 'high', 'active',
  'none', null, 5, array[200], 1
),
(
  'neweix-shop', 'Neweix Shop', 'Standalone commerce repository for storefront, checkout, order lifecycle, delivery integrations and Shop administration. Repository foundation and feature migration are in progress; production deployment is not implied.',
  'github', 'neweix24/shop', 'main', 'https://github.com/neweix24/shop',
  'Neweix Shop', 'confidential', 'high', 'planned',
  'none', null, 5, array[200], 1
),
(
  'eixon', 'Eixon', 'Separate financial and reward system for EixPay wallet/ledger, EixVerse missions and related modules. Current repository is a source extraction and is not yet a standalone deployable application.',
  'github', 'neweix24/eixon', 'main', 'https://github.com/neweix24/eixon',
  'Eixon', 'restricted', 'critical', 'planned',
  'none', null, 5, array[200], 1
),
(
  'neweix-account', 'Neweix Account', 'Customer-only account and authentication service. Supreme and future employee identities are provisioned and authorized independently.',
  'github', 'neweix24/account', 'main', 'https://github.com/neweix24/account',
  'Neweix Account', 'restricted', 'critical', 'planned',
  'none', null, 5, array[200], 1
),
(
  'neweix-message', 'Neweix Message', 'Planned messaging service. Repository and integration adapter have not yet been identified, so no repository or operational capability is enabled.',
  null, null, null, null,
  'Neweix Message', 'confidential', 'high', 'planned',
  'none', null, 5, array[200], 1
),
(
  'supreme', 'Supreme', 'Central service control plane for the Neweix ecosystem. The registry and Android application are under implementation; provider-specific execution adapters are not yet enabled.',
  'github', 'neweix24/supreme', 'main', 'https://github.com/neweix24/supreme',
  'Supreme', 'restricted', 'high', 'planned',
  'none', null, 5, array[200], 1
)
on conflict (service_id) do nothing;

insert into supreme.service_environments (
  service_id, environment_id, classification, api_base_url, enabled
) values
  ('neweix', 'production', 'production', 'https://neweix.com', true),
  ('neweix-shop', 'development', 'development', null, false),
  ('eixon', 'development', 'development', null, false),
  ('neweix-account', 'development', 'development', null, false),
  ('neweix-message', 'development', 'development', null, false),
  ('supreme', 'development', 'development', null, false)
on conflict (service_id, environment_id) do nothing;

insert into supreme.audit_events (
  actor_user_id, action, outcome, policy_version, details
)
select
  s.user_id,
  'registry.bootstrap',
  'success',
  'v1',
  jsonb_build_object(
    'services_registered', array['neweix', 'neweix-shop', 'eixon', 'neweix-account', 'neweix-message', 'supreme'],
    'capabilities_enabled', false,
    'note', 'Initial registry metadata only; no provider operation adapters are enabled.'
  )
from public.staff_profiles s
where s.role = 'supreme' and s.is_active = true and s.public_id = 'supreme'
limit 1;
