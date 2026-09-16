-- An organization must always keep an owner, and deleting an account must not be able to break
-- that. The rule lives in the database because the cascade from `users` to `organization_members`
-- is what does the damage: it runs inside the delete, so no check outside the transaction can
-- close the window. Enforcing it here also covers the bootstrap command and psql.
CREATE OR REPLACE FUNCTION prevent_orphaned_organization() RETURNS trigger AS $$
DECLARE
    orphaned TEXT;
BEGIN
    SELECT string_agg(organizations.name, ', ' ORDER BY organizations.name)
    INTO orphaned
    FROM organization_members
    JOIN organizations ON organizations.id = organization_members.organization_id
    WHERE organization_members.user_id = OLD.id
      AND organization_members.role = 'owner'
      AND NOT EXISTS (
          SELECT 1
          FROM organization_members AS successor
          WHERE successor.organization_id = organization_members.organization_id
            AND successor.role = 'owner'
            AND successor.user_id <> OLD.id
      );

    IF orphaned IS NOT NULL THEN
        -- A dedicated SQLSTATE so the API can turn this into a 400 with the message below,
        -- rather than reporting a generic internal failure.
        RAISE EXCEPTION 'this account is the last owner of: %', orphaned
            USING ERRCODE = 'SS001',
                  HINT = 'give ownership to another member first, or delete the organization';
    END IF;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Fires before the cascade, so the memberships are still there to be inspected.
CREATE TRIGGER users_prevent_orphaned_organization
    BEFORE DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION prevent_orphaned_organization();
