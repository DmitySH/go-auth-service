CREATE TABLE "auth_user"
(
    "id"       BIGSERIAL PRIMARY KEY,
    "email"    VARCHAR(128) NOT NULL UNIQUE,
    "password" CHAR(60)  NOT NULL
);

CREATE INDEX ON "auth_user" ("email");
