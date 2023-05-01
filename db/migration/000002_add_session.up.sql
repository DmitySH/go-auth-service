CREATE TABLE "session"
(
    "id"          UUID PRIMARY KEY,
    "user_id"      BIGSERIAL REFERENCES "auth_user" (id) ON DELETE CASCADE,
    "fingerprint" UUID NOT NULL
);
