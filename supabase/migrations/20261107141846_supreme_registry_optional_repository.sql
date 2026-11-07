-- Allow planned ecosystem services to be registered before a code repository exists.
alter table supreme.services
  alter column repository_provider drop not null,
  alter column repository_full_name drop not null,
  alter column repository_default_branch drop not null;

alter table supreme.services
  add constraint services_repository_fields_consistent check (
    (
      repository_provider is null
      and repository_full_name is null
      and repository_default_branch is null
      and repository_url is null
    )
    or
    (
      repository_provider is not null
      and repository_full_name is not null
      and repository_default_branch is not null
    )
  );
