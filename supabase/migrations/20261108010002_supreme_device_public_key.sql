-- Persist only the public key extracted from a certificate chain that has
-- already passed Google's Android attestation, revocation, key-policy and
-- proof-of-possession verification. The corresponding private key never leaves
-- Android Keystore. Legacy device registrations remain nullable and must
-- re-attest before transaction authorization can be enabled.
alter table supreme.devices
  add column if not exists device_public_key_spki bytea;

alter table supreme.devices
  drop constraint if exists supreme_devices_public_key_spki_size;

alter table supreme.devices
  add constraint supreme_devices_public_key_spki_size
  check (
    device_public_key_spki is null
    or octet_length(device_public_key_spki) between 64 and 256
  );

comment on column supreme.devices.device_public_key_spki is
  'DER SubjectPublicKeyInfo public key extracted from a Google-trusted Android hardware-attestation leaf certificate; nullable for legacy registrations pending re-attestation. Never contains private key material.';
