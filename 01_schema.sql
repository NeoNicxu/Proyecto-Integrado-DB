-- =====================================================================
-- Esquema offline-first para técnicos agrícolas (PostgreSQL / Supabase)
-- Ejecutar en: Supabase > SQL Editor
-- Requisito: el rol app_backend ya existe (se creó en el paso anterior).
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Infraestructura de sincronización
-- ---------------------------------------------------------------------
-- Secuencia global: cada escritura recibe un número creciente. El cliente
-- guarda "el último número que vi" y pide solo lo que sea mayor.
-- Es más fiable que comparar relojes de dispositivos (que se desfasan).
CREATE ROLE app_backend;

create sequence if not exists public.sync_seq;

create or replace function public.set_sync_columns()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.server_version := nextval('public.sync_seq');
  new.updated_at     := now();
  return new;
end;
$$;

-- ---------------------------------------------------------------------
-- 2. Tablas
-- ---------------------------------------------------------------------

-- Técnicos: NO se sincroniza con el cliente (solo login en el backend).
create table if not exists public.tecnicos (
  id            uuid primary key default gen_random_uuid(),
  nombre        text not null,
  email         text not null unique,
  password_hash text not null,
  activo        boolean not null default true,
  created_at    timestamptz not null default now()
);

-- Parcelas. El id (UUID) lo genera el CLIENTE con crypto.randomUUID(),
-- así puede crear registros sin conexión sin chocar con otros dispositivos.
create table if not exists public.parcelas (
  id            uuid primary key,
  tecnico_id    uuid not null references public.tecnicos(id),
  nombre        text not null,
  cultivo       text,
  superficie_ha numeric(10,2) check (superficie_ha is null or superficie_ha >= 0),
  latitud       double precision check (latitud  between -90  and 90),
  longitud      double precision check (longitud between -180 and 180),
  notas         text,
  -- columnas de sincronización
  client_updated_at timestamptz not null,           -- hora del dispositivo al editar
  deleted_at        timestamptz,                    -- borrado lógico (tombstone)
  updated_at        timestamptz not null default now(),
  server_version    bigint not null default 0,      -- lo asigna el trigger
  -- permite que visitas verifique que la parcela es del mismo técnico
  unique (id, tecnico_id)
);

create table if not exists public.visitas (
  id                uuid primary key,
  tecnico_id        uuid not null references public.tecnicos(id),
  parcela_id        uuid not null,
  fecha_visita      timestamptz not null,
  estado_cultivo    text,
  plagas_detectadas text,
  recomendaciones   text,
  -- columnas de sincronización
  client_updated_at timestamptz not null,
  deleted_at        timestamptz,
  updated_at        timestamptz not null default now(),
  server_version    bigint not null default 0,
  -- FK compuesta: una visita solo puede apuntar a una parcela del MISMO técnico
  foreign key (parcela_id, tecnico_id) references public.parcelas (id, tecnico_id)
);

-- Índices para el "pull" (filtra por técnico y por server_version)
create index if not exists idx_parcelas_sync on public.parcelas (tecnico_id, server_version);
create index if not exists idx_visitas_sync  on public.visitas  (tecnico_id, server_version);
create index if not exists idx_visitas_parcela on public.visitas (parcela_id);

-- Triggers que asignan server_version / updated_at en cada INSERT o UPDATE
drop trigger if exists trg_parcelas_sync on public.parcelas;
create trigger trg_parcelas_sync
  before insert or update on public.parcelas
  for each row execute function public.set_sync_columns();

drop trigger if exists trg_visitas_sync on public.visitas;
create trigger trg_visitas_sync
  before insert or update on public.visitas
  for each row execute function public.set_sync_columns();

-- ---------------------------------------------------------------------
-- 3. Permisos mínimos para el rol del backend
--    (sin DELETE: el borrado es lógico mediante deleted_at)
-- ---------------------------------------------------------------------
grant usage on schema public to app_backend;
grant select                 on public.tecnicos to app_backend;
grant select, insert, update on public.parcelas, public.visitas to app_backend;
grant usage, select on sequence public.sync_seq to app_backend;

-- ---------------------------------------------------------------------
-- 4. RLS: solo app_backend tiene política; anon/authenticated quedan fuera
-- ---------------------------------------------------------------------
alter table public.tecnicos enable row level security;
alter table public.parcelas enable row level security;
alter table public.visitas  enable row level security;

drop policy if exists backend_all on public.tecnicos;
create policy backend_all on public.tecnicos
  for all to app_backend using (true) with check (true);

drop policy if exists backend_all on public.parcelas;
create policy backend_all on public.parcelas
  for all to app_backend using (true) with check (true);

drop policy if exists backend_all on public.visitas;
create policy backend_all on public.visitas
  for all to app_backend using (true) with check (true);

-- Cierra la Data API pública (clave publishable / anon)
revoke all on public.tecnicos, public.parcelas, public.visitas from anon, authenticated;
revoke all on sequence public.sync_seq from anon, authenticated;

-- ==========================================
-- ROLES DE SEGURIDAD Y PRIVILEGIOS MÍNIMOS
-- ==========================================

-- 1. Creación de roles
CREATE ROLE admin_app;
CREATE ROLE tecnico_app;

-- 2. Permisos para el Administrador (CRUD Total)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO admin_app;

-- 3. Permisos restrictivos para el Técnico (Solo lectura de Obras e ingreso de Checklists)
GRANT SELECT ON parcelas TO tecnico_app;
GRANT INSERT ON visitas TO tecnico_app;

-- 4. Denegación explícita para prevenir inyecciones o alteraciones
REVOKE UPDATE, DELETE ON parcelas FROM tecnico_app;
REVOKE UPDATE, DELETE ON visitas FROM tecnico_app;
GRANT INSERT ON visitas TO tecnico_app;