-- Support the per-device rolling-window limiter for biometric decision challenges.
-- The API takes a transaction-scoped advisory lock per user/device before
-- counting and inserting, so concurrent challenge requests cannot race the cap.
create index if not exists supreme_control_decision_challenges_device_created_idx
  on supreme.control_decision_challenges (user_id, device_id, created_at desc);

comment on index supreme.supreme_control_decision_challenges_device_created_idx is
  'Supports the atomic rolling 10-minute limit of 10 biometric decision challenges per Supreme device.';
