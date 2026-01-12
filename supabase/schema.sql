create extension if not exists "pgcrypto";

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  nome text not null,
  foto_perfil text,
  endereco text,
  colegio text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

alter table public.profiles
  add column if not exists foto_perfil text;

create table if not exists public.activities (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  prompt text not null,
  atividade_gerada text not null,
  compartilhar boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

create table if not exists public.anonymous_requests (
  id uuid primary key default gen_random_uuid(),
  ip text not null,
  route text not null,
  requested_at timestamp with time zone default now()
);

create index if not exists idx_anonymous_requests_ip_route_date
  on public.anonymous_requests (ip, route, requested_at);

create table if not exists public.feedback (
  id uuid primary key default gen_random_uuid(),
  created_at timestamp with time zone not null default now(),
  prompt text not null,
  serie text not null,
  resposta text not null,
  utilidade text not null,
  comentario text
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, nome, foto_perfil, endereco, colegio)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'nome', 'Sem nome'),
    new.raw_user_meta_data->>'foto_perfil',
    new.raw_user_meta_data->>'endereco',
    new.raw_user_meta_data->>'colegio'
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

drop trigger if exists set_profiles_updated_at on public.profiles;
create trigger set_profiles_updated_at
  before update on public.profiles
  for each row execute procedure public.set_updated_at();

drop trigger if exists set_activities_updated_at on public.activities;
create trigger set_activities_updated_at
  before update on public.activities
  for each row execute procedure public.set_updated_at();

alter table public.profiles enable row level security;
alter table public.activities enable row level security;

drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile"
  on public.profiles for select
  using (auth.uid() = id);

drop policy if exists "Users can update own profile" on public.profiles;
create policy "Users can update own profile"
  on public.profiles for update
  using (auth.uid() = id);

drop policy if exists "Users can manage own activities" on public.activities;
create policy "Users can manage own activities"
  on public.activities for all
  using (auth.uid() = user_id);
