create or replace function jwt_claim(c text) returns text as $$
select current_setting('request.jwt.claim.' || c, true);
$$ stable language sql;

create or replace function current_user_name() returns text as $$
select
    case coalesce(jwt_claim('sub'),'')
        when '' then 'anonymous'
        else jwt_claim('sub')
        end
$$ stable language sql;

create role api;

create schema data;
create table data.comment(
    id bigserial primary key,
    text varchar(255) not null,
    author varchar(255) not null default current_user_name()
);

alter table data.comment enable row level security;
-- define the RLS policy controlling what rows are visible to a particular application user
create policy comment_access_policy on data.comment to api
    using (
        current_user_name() = author
    )
    with check (
    -- users can only update/delete their own comments
    (current_user_name() = author)
    );


create schema api;
create view api.comment as (select * from data.comment);
alter view api.comment owner to api;

grant usage on schema api to api;
-- grant select,insert,update on api.comment to api;
grant select,insert,update on data.comment to api;