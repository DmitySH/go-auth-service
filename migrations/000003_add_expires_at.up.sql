ALTER TABLE "session" ADD COLUMN expires_at TIMESTAMP NOT NULL DEFAULT now();