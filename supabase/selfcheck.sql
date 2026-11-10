-- Security self-check for the SecureShare Pro database.
--
-- Run this after any schema change. Every row must read passed = true.
-- It asserts the invariants the app depends on, in particular that the
-- `anon` role — the only role the browser can act as — can reach exactly
-- three functions and no table at all.
--
--   select * from ( <this file> ) t;                -- eyeball every row
--   select bool_and(passed) from ( <this file> ) t; -- one boolean answer
--
-- Deliberately a query, not a stored function: a check that has to prove the
-- attack surface has not grown should not itself add to it.

with
anon_fns as (
    select p.proname
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public'
       and has_function_privilege('anon', p.oid, 'EXECUTE')
),
anon_tables as (
    select c.relname
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public'
       and c.relkind in ('r', 'v', 'm', 'p')
       and (has_table_privilege('anon', c.oid, 'SELECT')
         or has_table_privilege('anon', c.oid, 'INSERT')
         or has_table_privilege('anon', c.oid, 'UPDATE')
         or has_table_privilege('anon', c.oid, 'DELETE'))
)
select 'anon can reach no table'::text as check_name,
       (select count(*) from anon_tables) = 0 as passed,
       coalesce('granted on: ' || (select string_agg(relname, ', ') from anon_tables),
                'no table privileges')::text as detail

union all

select 'anon can execute exactly create_clip, read_clip, redeem_pin',
       coalesce((select array_agg(proname order by proname) from anon_fns), '{}'::name[])
         = array['create_clip', 'read_clip', 'redeem_pin']::name[],
       'executable: ' || coalesce((select string_agg(proname, ', ' order by proname) from anon_fns), 'none')

union all

select 'RLS is forced on public.clips',
       (select relrowsecurity and relforcerowsecurity from pg_class where oid = 'public.clips'::regclass),
       'rowsecurity/forcerowsecurity: ' ||
       (select relrowsecurity || '/' || relforcerowsecurity from pg_class where oid = 'public.clips'::regclass)::text

union all

select 'two restrictive deny-all policies guard public.clips',
       (select count(*) = 2 from pg_policy p join pg_class c on c.oid = p.polrelid
         where c.oid = 'public.clips'::regclass and not p.polpermissive),
       'restrictive policies: ' ||
       (select count(*) from pg_policy p join pg_class c on c.oid = p.polrelid
         where c.oid = 'public.clips'::regclass and not p.polpermissive)::text

union all

select 'pin wrap is constrained to match the clip mode',
       exists (select 1 from pg_constraint where conname = 'clips_pin_wrap_matches_mode'),
       case when exists (select 1 from pg_constraint where conname = 'clips_pin_wrap_matches_mode')
            then 'clips_pin_wrap_matches_mode present' else 'MISSING' end

union all

select 'PIN pepper lives only in Vault',
       (select count(*) from vault.secrets where name = 'pin_pepper') = 1
       and (select count(*) from private.config where key = 'pin_pepper') = 0,
       'vault copies: ' || (select count(*) from vault.secrets where name = 'pin_pepper')::text
       || ', plain-table copies: ' || (select count(*) from private.config where key = 'pin_pepper')::text

union all

select 'expired clips are purged on a schedule',
       exists (select 1 from cron.job where jobname = 'purge-expired-clips' and active),
       case when exists (select 1 from cron.job where jobname = 'purge-expired-clips' and active)
            then 'pg_cron job active' else 'NO ACTIVE PURGE JOB' end

union all

select 'anon cannot touch the private schema',
       not has_schema_privilege('anon', 'private', 'USAGE'),
       'private usage: ' || has_schema_privilege('anon', 'private', 'USAGE')::text

order by check_name;
