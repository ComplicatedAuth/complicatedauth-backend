CREATE TABLE platform_operator_actions (
    uid uuid PRIMARY KEY,
    actor text NOT NULL CHECK (length(actor) BETWEEN 1 AND 200),
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]{0,127}$'),
    target_type text NOT NULL CHECK (target_type ~ '^[a-z][a-z0-9_]{0,62}$'),
    target_uid uuid NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 10 AND 1000),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX platform_operator_actions_created_idx
    ON platform_operator_actions(created_at DESC, uid DESC);
CREATE INDEX platform_operator_actions_target_idx
    ON platform_operator_actions(target_type, target_uid, created_at DESC, uid DESC);

CREATE FUNCTION reject_platform_operator_action_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'platform operator actions are immutable';
END;
$$;
CREATE TRIGGER platform_operator_actions_immutable
    BEFORE UPDATE OR DELETE ON platform_operator_actions
    FOR EACH ROW EXECUTE FUNCTION reject_platform_operator_action_mutation();
