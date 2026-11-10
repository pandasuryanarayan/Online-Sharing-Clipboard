-- SecureShare Pro — complete database schema.
--
-- Reconstructed from the live catalogue of the production project, not from
-- memory, so it matches what is actually running. Run this top to bottom against
-- a fresh Supabase project to rebuild the database; then run
-- `supabase/selfcheck.sql` and confirm every row reads passed = true.
--
-- Requires the pgcrypto, pg_cron and supabase_vault extensions, all of which
-- Supabase makes available. Nothing here contains a secret: the PIN pepper is
-- generated locally by this script and stored in Vault, never committed.
--
-- Object inventory (keep in sync if you add anything):
--   public.clips              the only table
--   public.create_clip()      insert a clip
--   public.read_clip()        consume a view by id
--   public.redeem_pin()       consume a view by PIN
--   public.secure_ip_hash()   internal: hashed client IP for rate limiting
--   private.pin_lookup()      internal: keyed HMAC of a PIN
--   private.retire_pin()      internal: trigger that retires a PIN on delete
--   private.config, private.pin_attempts, private.pin_history

-- ---------------------------------------------------------------------------
-- 1. Extensions
-- ---------------------------------------------------------------------------

create extension if not exists pgcrypto;
create extension if not exists pg_cron;

-- ---------------------------------------------------------------------------
-- 2. Private schema — never exposed through the API
-- ---------------------------------------------------------------------------

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 3. The clips table
-- ---------------------------------------------------------------------------

create table if not exists public.clips (
    id          uuid        primary key default gen_random_uuid(),
    ciphertext  text        not null,
    iv          text        not null,
    salt        text,
    mode        text        not null,
    expires_at  timestamptz,
    max_views   integer,
    views       integer     not null default 0,
    created_at  timestamptz not null default now(),
    creator_ip  text,
    pin_lookup  text,
    pin_wrapped text,
    pin_salt    text,
    constraint clips_mode_check check (mode in ('k', 'p')),
    constraint clips_max_views_check check (max_views is null or (max_views >= 1 and max_views <= 1000)),
    constraint clips_payload_size check (length(ciphertext) >= 1 and length(ciphertext) <= 200000),
    -- A PIN-bearing clip either carries a wrapped key (key mode) or carries
    -- none at all (password mode). Anything else is a bug, so refuse to store it.
    constraint clips_pin_wrap_matches_mode check (
        pin_lookup is null
        or (mode = 'k' and pin_wrapped is not null and pin_salt is not null)
        or (mode = 'p' and pin_wrapped is null and pin_salt is null)
    )
);

create index if not exists clips_expires_at_idx on public.clips (expires_at);
create index if not exists clips_created_at_idx on public.clips (created_at);
create index if not exists clips_creator_ip_idx on public.clips (creator_ip, created_at);

-- One live clip per PIN. Partial so the many NULLs do not collide.
create unique index if not exists clips_pin_lookup_key
    on public.clips (pin_lookup)
    where pin_lookup is not null;

-- ---------------------------------------------------------------------------
-- 4. Private tables
-- ---------------------------------------------------------------------------

create table if not exists private.config (
    key   text primary key,
    value text not null
);

create table if not exists private.pin_attempts (
    id           bigserial primary key,
    ip_hash      text        not null,
    attempted_at timestamptz not null default now()
);

create index if not exists pin_attempts_ip_idx on private.pin_attempts (ip_hash, attempted_at);
create index if not exists pin_attempts_time_idx on private.pin_attempts (attempted_at);

create table if not exists private.pin_history (
    pin_lookup text        primary key,
    retired_at timestamptz not null default now()
);

revoke all on private.config, private.pin_attempts, private.pin_history
    from public, anon, authenticated;
revoke all on sequence private.pin_attempts_id_seq
    from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 5. Row level security — forced, with restrictive deny-all policies
-- ---------------------------------------------------------------------------

alter table public.clips enable row level security;
alter table public.clips force row level security;

-- Restrictive, so they are ANDed with any permissive policy added later rather
-- than ORed: a future mistake cannot open the table.
drop policy if exists clips_deny_all_anon on public.clips;
create policy clips_deny_all_anon on public.clips
    as restrictive for all to anon
    using (false) with check (false);

drop policy if exists clips_deny_all_authenticated on public.clips;
create policy clips_deny_all_authenticated on public.clips
    as restrictive for all to authenticated
    using (false) with check (false);

revoke all on public.clips from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 6. Internal helpers
-- ---------------------------------------------------------------------------

-- The client address must not be forgeable, or every per-IP rate limit below can be
-- bypassed by rotating a fake hop. cf-connecting-ip is preferred because Cloudflare
-- overwrites it with the real peer; otherwise the last hop of x-forwarded-for is
-- used, since proxies append and only the final entry comes from a trusted proxy.
create or replace function public.secure_ip_hash()
returns text
language plpgsql
stable
set search_path = public, extensions, pg_temp
as $$
declare
    v_headers jsonb;
    v_ip text;
    v_xff text;
begin
    v_headers := coalesce(nullif(current_setting('request.headers', true), ''), '{}')::jsonb;

    -- Cloudflare sets this and overwrites any client-supplied value.
    v_ip := trim(coalesce(v_headers ->> 'cf-connecting-ip', ''));

    if v_ip = '' then
        -- Proxies append, so the last hop is the one added closest to the server;
        -- everything before it is client-controlled and must not be trusted.
        v_xff := coalesce(v_headers ->> 'x-forwarded-for', '');
        v_ip := trim(regexp_replace(v_xff, '^.*,', ''));
    end if;

    if v_ip = '' then
        v_ip := 'unknown';
    end if;

    return encode(digest(v_ip, 'sha256'), 'hex');
end;
$$;

create or replace function private.pin_lookup(p_pin text)
returns text
language plpgsql
stable
security definer
set search_path = private, extensions, vault, pg_temp
as $$
declare
    v_pepper text;
begin
    select decrypted_secret into v_pepper
      from vault.decrypted_secrets
     where name = 'pin_pepper'
     limit 1;

    if v_pepper is null then
        raise exception 'pin_pepper_missing';
    end if;

    return encode(hmac(p_pin, v_pepper, 'sha256'), 'hex');
end;
$$;

create or replace function private.retire_pin()
returns trigger
language plpgsql
security definer
set search_path = private, pg_temp
as $$
begin
    if old.pin_lookup is not null then
        insert into private.pin_history (pin_lookup)
        values (old.pin_lookup)
        on conflict (pin_lookup) do update set retired_at = now();
    end if;
    return old;
end;
$$;

drop trigger if exists clips_retire_pin on public.clips;
create trigger clips_retire_pin
    before delete on public.clips
    for each row execute function private.retire_pin();

-- ---------------------------------------------------------------------------
-- 7. Public API — the only three things a browser can call
-- ---------------------------------------------------------------------------

create or replace function public.create_clip(
    p_ciphertext    text,
    p_iv            text,
    p_salt          text,
    p_mode          text,
    p_expires_at    timestamptz,
    p_max_views     integer,
    p_pin           text default null,
    p_pin_wrapped   text default null,
    p_pin_salt      text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, private, pg_temp
as $$
declare
    v_ip        text;
    v_recent    integer;
    v_live      integer;
    v_id        uuid;
    v_expires   timestamptz;
    v_max_views integer;
    v_lookup    text;
    v_asc       boolean;
    v_desc      boolean;
    i           integer;
    v_rate_limit constant integer := 30;
    v_max_hours  constant integer := 168;
    v_max_live   constant integer := 5000;
begin
    if p_mode not in ('k', 'p') then
        raise exception 'invalid_mode';
    end if;
    if p_mode = 'p' and (p_salt is null or length(p_salt) < 8) then
        raise exception 'missing_salt';
    end if;
    if p_ciphertext is null or length(p_ciphertext) < 8 then
        raise exception 'invalid_payload';
    end if;
    if p_iv is null or length(p_iv) < 8 then
        raise exception 'invalid_iv';
    end if;

    if p_pin is not null then
        if p_pin !~ '^[0-9]{5}$' then
            raise exception 'invalid_pin';
        end if;

        if p_pin ~ '^([0-9])\1{4}$' then
            raise exception 'weak_pin';
        end if;
        v_asc := true;
        v_desc := true;
        for i in 2..5 loop
            if substr(p_pin, i, 1)::int <> substr(p_pin, i - 1, 1)::int + 1 then
                v_asc := false;
            end if;
            if substr(p_pin, i, 1)::int <> substr(p_pin, i - 1, 1)::int - 1 then
                v_desc := false;
            end if;
        end loop;
        if v_asc or v_desc then
            raise exception 'weak_pin';
        end if;
        if p_pin in ('13579', '24680', '97531', '08642', '10101', '12121', '20202', '11223', '33221') then
            raise exception 'weak_pin';
        end if;

        if p_mode = 'k' then
            if p_pin_wrapped is null or length(p_pin_wrapped) < 8 then
                raise exception 'invalid_pin_wrapped';
            end if;
            if p_pin_salt is null or length(p_pin_salt) < 8 then
                raise exception 'invalid_pin_salt';
            end if;
        else
            if p_pin_wrapped is not null or p_pin_salt is not null then
                raise exception 'pin_wrap_not_allowed';
            end if;
        end if;

        v_lookup := private.pin_lookup(p_pin);

        -- Taken if a live clip holds it, or a clip that held it died recently.
        if exists (select 1 from public.clips where pin_lookup = v_lookup)
           or exists (select 1 from private.pin_history where pin_lookup = v_lookup) then
            raise exception 'pin_taken';
        end if;
    end if;

    v_expires := p_expires_at;
    if v_expires is not null then
        if v_expires <= now() then
            raise exception 'invalid_expiry';
        end if;
        if v_expires > now() + make_interval(hours => v_max_hours) then
            raise exception 'invalid_expiry';
        end if;
    end if;

    v_max_views := p_max_views;
    if v_max_views is not null and (v_max_views < 1 or v_max_views > 1000) then
        raise exception 'invalid_max_views';
    end if;

    select count(*) into v_live from public.clips;
    if v_live >= v_max_live then
        raise exception 'at_capacity';
    end if;

    v_ip := public.secure_ip_hash();

    select count(*) into v_recent
      from public.clips
     where creator_ip = v_ip
       and created_at > now() - interval '1 hour';

    if v_recent >= v_rate_limit then
        raise exception 'rate_limited';
    end if;

    delete from public.clips
     where id in (
        select id from public.clips
         where expires_at is not null and expires_at <= now()
         limit 100
     );

    insert into public.clips (
        ciphertext, iv, salt, mode, expires_at, max_views, creator_ip,
        pin_lookup, pin_wrapped, pin_salt
    )
    values (
        p_ciphertext, p_iv, p_salt, p_mode, v_expires, v_max_views, v_ip,
        v_lookup, p_pin_wrapped, p_pin_salt
    )
    returning id into v_id;

    return jsonb_build_object(
        'id', v_id,
        'expires_at', v_expires,
        'max_views', v_max_views,
        'has_pin', v_lookup is not null
    );
end;
$$;

create or replace function public.read_clip(p_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
    v_row   public.clips%rowtype;
    v_left  integer;
begin
    update public.clips
       set views = views + 1
     where id = p_id
       and (expires_at is null or expires_at > now())
       and (max_views is null or views < max_views)
    returning * into v_row;

    if v_row.id is null then
        if exists (select 1 from public.clips where id = p_id) then
            raise exception 'clip_gone';
        end if;
        raise exception 'clip_not_found';
    end if;

    if v_row.max_views is not null and v_row.views >= v_row.max_views then
        delete from public.clips where id = v_row.id;
        v_left := 0;
    else
        v_left := case when v_row.max_views is null then null else v_row.max_views - v_row.views end;
    end if;

    return jsonb_build_object(
        'ciphertext', v_row.ciphertext,
        'iv', v_row.iv,
        'salt', v_row.salt,
        'mode', v_row.mode,
        'expires_at', v_row.expires_at,
        'views', v_row.views,
        'views_left', v_left
    );
end;
$$;

create or replace function public.redeem_pin(p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, private, pg_temp
as $$
declare
    v_ip         text;
    v_recent_ip  integer;
    v_recent_all integer;
    v_row        public.clips%rowtype;
    v_left       integer;
    v_lookup     text;
    v_ip_limit     constant integer := 10;
    v_global_limit constant integer := 300;
begin
    v_ip := public.secure_ip_hash();

    select count(*) into v_recent_ip
      from private.pin_attempts
     where ip_hash = v_ip
       and attempted_at > now() - interval '1 hour';
    if v_recent_ip >= v_ip_limit then
        raise exception 'rate_limited';
    end if;

    select count(*) into v_recent_all
      from private.pin_attempts
     where attempted_at > now() - interval '1 hour';
    if v_recent_all >= v_global_limit then
        raise exception 'rate_limited';
    end if;

    insert into private.pin_attempts (ip_hash) values (v_ip);
    delete from private.pin_attempts where attempted_at < now() - interval '2 hours';

    -- 4 digits stays accepted so any PIN issued before the change still works.
    if p_pin is null or p_pin !~ '^[0-9]{4,5}$' then
        return jsonb_build_object('ok', false, 'error', 'invalid_pin');
    end if;

    v_lookup := private.pin_lookup(p_pin);

    update public.clips
       set views = views + 1
     where pin_lookup = v_lookup
       and (expires_at is null or expires_at > now())
       and (max_views is null or views < max_views)
    returning * into v_row;

    if v_row.id is null then
        return jsonb_build_object('ok', false, 'error', 'invalid_pin');
    end if;

    if v_row.max_views is not null and v_row.views >= v_row.max_views then
        delete from public.clips where id = v_row.id;
        v_left := 0;
    else
        v_left := case when v_row.max_views is null then null else v_row.max_views - v_row.views end;
    end if;

    -- Password clips hand back no wrapped key: the PIN found the row, the
    -- password is still needed to derive the key.
    return jsonb_build_object(
        'ok', true,
        'mode', v_row.mode,
        'ciphertext', v_row.ciphertext,
        'iv', v_row.iv,
        'salt', v_row.salt,
        'pin_wrapped', v_row.pin_wrapped,
        'pin_salt', v_row.pin_salt,
        'expires_at', v_row.expires_at,
        'views_left', v_left
    );
end;
$$;

-- ---------------------------------------------------------------------------
-- 8. Privileges — exactly three functions, no tables
-- ---------------------------------------------------------------------------

-- Functions get EXECUTE for PUBLIC by default. Revoke that first, then grant to
-- precisely the roles that need it, so the surface is minimal rather than merely
-- "reachable by the right people anyway".
revoke execute on function public.create_clip(text, text, text, text, timestamptz, integer, text, text, text)
    from public, anon, authenticated;
revoke execute on function public.read_clip(uuid) from public, anon, authenticated;
revoke execute on function public.redeem_pin(text) from public, anon, authenticated;
revoke execute on function public.secure_ip_hash() from public, anon, authenticated;
revoke execute on function private.pin_lookup(text) from public, anon, authenticated;
revoke execute on function private.retire_pin() from public, anon, authenticated;

grant execute on function public.create_clip(text, text, text, text, timestamptz, integer, text, text, text)
    to anon, authenticated, service_role;
grant execute on function public.read_clip(uuid) to anon, authenticated, service_role;
grant execute on function public.redeem_pin(text) to anon, authenticated, service_role;

-- Supabase grants every new table, function and sequence in `public` to anon and
-- authenticated by default. That is the opposite of this project's model, so the
-- default is inverted: anything created later starts closed and must be granted
-- deliberately. Existing objects are unaffected.
alter default privileges for role postgres in schema public
    revoke all on tables from anon, authenticated;
alter default privileges for role postgres in schema public
    revoke all on sequences from anon, authenticated;
alter default privileges for role postgres in schema public
    revoke all on functions from anon, authenticated;

-- ---------------------------------------------------------------------------
-- 9. Documentation that shows up in the dashboard
-- ---------------------------------------------------------------------------

comment on table public.clips is
    'Encrypted clips. RLS forced, restrictive deny-all policies: reachable only through the SECURITY DEFINER functions below.';

comment on column public.clips.pin_lookup is
    'Keyed HMAC-SHA256 of the 5-digit PIN (never the PIN itself). NULL = clip has no PIN.';

comment on column public.clips.pin_wrapped is
    'Content key encrypted under a key derived from the PIN. Filled ONLY for key-mode clips (no password), which is what lets a PIN alone decrypt. NULL for password clips: there the PIN only locates the row and the password does the unlocking.';

comment on column public.clips.pin_salt is
    'PBKDF2 salt used with the PIN to unwrap pin_wrapped. Key mode only, NULL for password clips.';

-- ---------------------------------------------------------------------------
-- 10. The PIN pepper — generated here, never committed
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (select 1 from vault.secrets where name = 'pin_pepper') then
        perform vault.create_secret(
            encode(gen_random_bytes(32), 'hex'),
            'pin_pepper',
            'Pepper for the keyed HMAC that looks up clips by PIN.'
        );
    end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- 11. Resource limits on the API roles
-- ---------------------------------------------------------------------------

alter role anon set statement_timeout = '3s';
alter role anon set idle_in_transaction_session_timeout = '10s';
alter role authenticated set statement_timeout = '3s';
alter role authenticated set idle_in_transaction_session_timeout = '10s';

-- ---------------------------------------------------------------------------
-- 12. Expiry actually happens on a schedule
-- ---------------------------------------------------------------------------

select cron.unschedule(jobid)
from cron.job
where jobname = 'purge-expired-clips';

select cron.schedule(
    'purge-expired-clips',
    '*/15 * * * *',
    $job$
    delete from public.clips
     where expires_at is not null
       and expires_at <= now();

    delete from private.pin_attempts
     where attempted_at < now() - interval '2 hours';

    delete from private.pin_history
     where retired_at < now() - interval '30 days';
    $job$
);
