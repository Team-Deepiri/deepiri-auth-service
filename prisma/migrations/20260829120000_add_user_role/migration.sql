-- Portal RBAC: one role per user.
--   member                       -- default, no team assigned
--   ai_ml | qa_support | software_developer | it   -- self-selectable team roles
--   leadership | admin           -- granted via PUT /users/:id/role
--   owner                        -- set in the database only (this file)

-- AlterTable
ALTER TABLE "users" ADD COLUMN "role" VARCHAR(50) NOT NULL DEFAULT 'member';

-- CreateIndex
CREATE INDEX "users_role_idx" ON "users"("role");

-- Bootstrap the initial owner + admin. One-off data step: `prisma migrate deploy`
-- records this migration in _prisma_migrations and never re-runs it. Matched by a
-- stable id (Joe's existing account) and by email; a no-op if the row is absent.
UPDATE "users" SET "role" = 'owner'
  WHERE "id" = '52d7a6e8-d1c0-497a-9d18-fc68894da710';   -- joeblack (Joe Black)
UPDATE "users" SET "role" = 'admin'
  WHERE "email" = 'lidavid207@gmail.com';                 -- David
