create table identity
(
    id       uuid primary key,
    username text not null unique,
    password text not null
);

create table session
(
    token    text        not null,
    identity uuid        not null references identity (id),
    expires  timestamptz not null,

    primary key (token, identity)
);

create table reset
(
    token    text        not null,
    identity uuid        not null references identity (id),
    expires  timestamptz not null,

    primary key (token, identity)
);