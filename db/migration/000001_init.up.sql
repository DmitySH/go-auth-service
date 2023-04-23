CREATE TABLE "auth_user"
(
    "id"       BIGSERIAL PRIMARY KEY,
    "email"    VARCHAR(128) NOT NULL UNIQUE,
    "password" VARCHAR(32)  NOT NULL UNIQUE
);

CREATE INDEX ON "auth_user" ("email");
