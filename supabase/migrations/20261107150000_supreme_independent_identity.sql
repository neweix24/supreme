-- Supreme owns one isolated ruler identity. This is not a customer or employee account.
-- Authentication credentials live in Supabase Auth; authorization mapping lives here.
create table if not exists supreme.identities (
  user_id uuid primary key references auth.users(id) on delete restrict,
  principal_id text not null default 'supreme' check (principal_id = 'supreme'),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- There can be only one active Supreme principal in the entire system.
create unique index if not exists supreme_one_active_principal
  on supreme.identities (principal_id)
  where is_active = true;

revoke all on supreme.identities from public, anon, authenticated;
grant select, insert, update, delete on supreme.identities to service_role;

alter table supreme.identities enable row level security;
