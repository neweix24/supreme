-- Legacy device registrations did not prove biometric-bound key authorization.
-- They must re-attest with the new BIOMETRIC_STRONG per-operation policy.
alter table supreme.devices
  add column if not exists device_key_biometric_auth_required boolean not null default false;

comment on column supreme.devices.device_key_biometric_auth_required is
  'True only after server-side Android KeyDescription verification confirms hardware-enforced biometric authentication for every key operation. Legacy devices remain false until re-attestation.';
