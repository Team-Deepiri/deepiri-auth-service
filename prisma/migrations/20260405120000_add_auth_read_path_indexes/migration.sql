-- Composite indexes for auth-service read-heavy query paths.
-- 1. Social connection queries filter by user_id + status, may add connection_type,
--    and order by updated_at DESC.
-- 2. Progress series queries filter by user_id + metric_type across a timestamp range.

CREATE INDEX "social_connections_user_id_status_connection_type_updated_at_idx"
ON "public"."social_connections" ("user_id", "status", "connection_type", "updated_at" DESC);

CREATE INDEX "progress_points_user_id_metric_type_timestamp_idx"
ON "public"."progress_points" ("user_id", "metric_type", "timestamp" DESC);
