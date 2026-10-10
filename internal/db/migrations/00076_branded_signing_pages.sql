-- +goose Up
-- Only the fresh per-render artifact may change in schema3. Approved master,
-- local assets, complete branding and intended recipient UUIDs remain immutable.
-- Existing migrations and schema1/2 source bytes are left intact.
LOCK TABLE documents, recipients, document_fields, document_branding_override IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION hash_guard_html_materialization_insert() RETURNS trigger AS $$
DECLARE d documents%ROWTYPE; p html_document_materializations%ROWTYPE;
BEGIN
    SELECT * INTO STRICT d FROM documents WHERE id = NEW.document_id AND org_id = NEW.org_id FOR UPDATE;
    IF d.html_source_json IS NULL OR d.source_kind <> 'pdf' OR d.status <> 'draft' OR d.deleted_at IS NOT NULL
       OR NEW.origin_commitment IS DISTINCT FROM decode(d.html_source_json ->> 'commitment', 'hex')
       OR NEW.source_commitment IS DISTINCT FROM decode(NEW.source_json ->> 'commitment', 'hex')
       OR NEW.pdf_key IS DISTINCT FROM NEW.source_json ->> 'pdf_key'
       OR NEW.pdf_sha256 IS DISTINCT FROM decode(NEW.source_json ->> 'pdf_sha256', 'hex')
       OR NEW.pdf_version_id IS DISTINCT FROM NEW.source_json ->> 'pdf_version_id'
       OR NEW.source_json ->> 'document_id' IS DISTINCT FROM d.id::text
       OR NEW.source_json ->> 'org_id' IS DISTINCT FROM d.org_id::text
       OR EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.created_by AND u.org_id <> d.org_id) THEN
        RAISE EXCEPTION 'HTML materialization identity is inconsistent' USING ERRCODE = '23514';
    END IF;
    IF NEW.sequence = 1 THEN
        IF d.html_current_materialization_id IS NOT NULL OR NEW.source_json IS DISTINCT FROM d.html_source_json THEN
            RAISE EXCEPTION 'HTML materialization origin is inconsistent' USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT * INTO STRICT p FROM html_document_materializations WHERE id = NEW.parent_id AND document_id = d.id AND org_id = d.org_id;
        IF p.sequence + 1 <> NEW.sequence OR p.source_commitment IS DISTINCT FROM NEW.parent_commitment
           OR d.html_current_materialization_id IS DISTINCT FROM p.id THEN
            RAISE EXCEPTION 'HTML materialization parent is not current' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF COALESCE(NEW.source_json->>'schema_version','') <> '3'
       AND NEW.source_json ? 'signing_artifact' THEN
        RAISE EXCEPTION 'Legacy source cannot carry signing artifact' USING ERRCODE = '23514';
    END IF;
    -- New text inputs never replace the original approved design/approval.
    IF (NEW.source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment','signing_artifact'])
        IS DISTINCT FROM (d.html_source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment','signing_artifact']) THEN
        RAISE EXCEPTION 'HTML materialization changed its approved origin' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION hash_check_branded_signing_page(target UUID) RETURNS void AS $$
DECLARE d documents%ROWTYPE; src JSONB; art JSONB; b JSONB; r JSONB; slot TEXT; rid UUID;
        expected_y NUMERIC; f RECORD; count_fields INTEGER; declaration JSONB;
BEGIN
    -- Legacy documents keep their original lock behavior. In particular,
    -- recipient-token revocation must not wait for a public PDF/field reader's
    -- parent SHARE lock merely because this policy is installed.
    SELECT * INTO d FROM documents WHERE id=target;
    IF NOT FOUND THEN RETURN; END IF;
    src := COALESCE(d.html_current_source_json,d.html_source_json);
    IF COALESCE(src->>'schema_version','') <> '3' THEN RETURN; END IF;
    -- Only policy-enabled documents take the serialization lock. Re-read the
    -- committed current projection after any wait before validating its pair.
    SELECT * INTO d FROM documents WHERE id=target FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    src := COALESCE(d.html_current_source_json,d.html_source_json);
    IF COALESCE(src->>'schema_version','') <> '3' THEN RETURN; END IF;
    art := src->'signing_artifact';
    IF d.source_kind<>'pdf' OR NOT d.requires_signature OR d.is_envelope
       OR jsonb_typeof(art) IS DISTINCT FROM 'object'
       OR art->>'version' IS DISTINCT FROM '1'
       OR art->>'policy' IS DISTINCT FROM 'hash-branded-signing-page-a4-v1'
       OR art->'composition'->>'output_sha256' IS DISTINCT FROM encode(d.pdf_sha256,'hex')
       OR (d.html_current_page_count IS NOT NULL AND art->'composition'->>'final_pages' IS DISTINCT FROM d.html_current_page_count::text)
       OR art->'fields' IS DISTINCT FROM jsonb_build_array(
           jsonb_build_object('slot','customer','page',(art->'composition'->>'final_pages')::int,'x',100000,'y',420000,'w',800000,'h',70000),
           jsonb_build_object('slot','provider','page',(art->'composition'->>'final_pages')::int,'x',100000,'y',790000,'w',800000,'h',70000)) THEN
        RAISE EXCEPTION 'Branded signing page artifact is inconsistent' USING ERRCODE='23514';
    END IF;
    SELECT count(*) INTO count_fields FROM document_fields WHERE document_id=d.id;
    IF count_fields<>2 THEN RAISE EXCEPTION 'Branded signing page requires its exact field pair' USING ERRCODE='23514'; END IF;
    IF (SELECT count(*) FROM recipients WHERE document_id=d.id)<>2 THEN
        RAISE EXCEPTION 'Branded signing page requires both intended recipients' USING ERRCODE='23514';
    END IF;
    FOREACH slot IN ARRAY ARRAY['customer','provider'] LOOP
        SELECT (x->>'recipient_id')::uuid INTO STRICT rid FROM jsonb_array_elements(src->'party_bindings') x WHERE x->>'slot'=slot;
        SELECT to_jsonb(x) INTO STRICT r FROM recipients x WHERE x.id=rid AND x.document_id=d.id AND x.role=slot;
        SELECT x INTO STRICT declaration FROM jsonb_array_elements(src->'master'->'contract_profile'->'parties') x WHERE x->>'slot'=slot;
        IF r->>'name' IS DISTINCT FROM src->'values'->>(declaration->>'representative_name')
           OR r->>'email' IS DISTINCT FROM src->'values'->>(declaration->>'representative_email') THEN
            RAISE EXCEPTION 'Branded signing page printed recipient identity drifted' USING ERRCODE='23514';
        END IF;
        SELECT * INTO STRICT f FROM document_fields WHERE document_id=d.id AND recipient_id=rid;
        expected_y := CASE WHEN slot='customer' THEN 42 ELSE 79 END;
        IF f.id='00000000-0000-0000-0000-000000000000'::uuid
           OR f.type<>'signature' OR NOT f.required OR f.page IS DISTINCT FROM (art->'composition'->>'final_pages')::int
           OR f.x_pct<>10 OR f.y_pct<>expected_y OR f.w_pct<>80 OR f.h_pct<>7
           OR f.label IS DISTINCT FROM initcap(slot)||' signature'
           OR f.options_json IS DISTINCT FROM jsonb_build_object('policy',art->>'policy','slot',slot,'source_commitment',src->>'commitment') THEN
            RAISE EXCEPTION 'Branded signing page field binding drifted' USING ERRCODE='23514';
        END IF;
    END LOOP;
    b := src->'master'->'signing_page'->'branding';
    IF b IS NULL OR b->>'logo_url' IS DISTINCT FROM '' OR b->>'logo_alt' IS DISTINCT FROM ''
       OR (SELECT jsonb_build_object('primary_hex',x.primary_hex,'accent_hex',x.accent_hex,'surface_hex',x.surface_hex,
              'text_hex',x.text_hex,'muted_hex',x.muted_hex,'logo_url',x.logo_url,'logo_alt',x.logo_alt,
              'font_heading',x.font_heading,'font_body',x.font_body,'signature_color',x.signature_color)
           FROM document_branding_override x WHERE x.document_id=d.id) IS DISTINCT FROM b THEN
        RAISE EXCEPTION 'Reviewed signing page branding drifted' USING ERRCODE='23514';
    END IF;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
    RAISE EXCEPTION 'Branded signing page requires its exact party and field bindings' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
CREATE FUNCTION hash_guard_branded_signing_page() RETURNS trigger AS $$
DECLARE target UUID;
BEGIN
    -- Status, token and field-value changes do not alter the frozen plan.
    -- Avoid a new parent serialization dependency for ordinary public reads,
    -- token revocation or filling an already-bound field.
    IF TG_OP='UPDATE' THEN
        IF TG_TABLE_NAME='recipients' THEN
            IF ROW(OLD.id,OLD.document_id,OLD.name,OLD.email,OLD.role)
               IS NOT DISTINCT FROM ROW(NEW.id,NEW.document_id,NEW.name,NEW.email,NEW.role) THEN
                RETURN NEW;
            END IF;
        ELSIF TG_TABLE_NAME='document_fields' THEN
            IF ROW(OLD.id,OLD.document_id,OLD.recipient_id,OLD.type,OLD.page,OLD.x_pct,OLD.y_pct,OLD.w_pct,OLD.h_pct,OLD.required,OLD.label,OLD.options_json)
               IS NOT DISTINCT FROM ROW(NEW.id,NEW.document_id,NEW.recipient_id,NEW.type,NEW.page,NEW.x_pct,NEW.y_pct,NEW.w_pct,NEW.h_pct,NEW.required,NEW.label,NEW.options_json) THEN
                RETURN NEW;
            END IF;
        END IF;
    END IF;
    IF TG_TABLE_NAME='documents' THEN
        target := CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;
    ELSE
        target := CASE WHEN TG_OP='DELETE' THEN OLD.document_id ELSE NEW.document_id END;
    END IF;
    PERFORM hash_check_branded_signing_page(target);
    IF TG_TABLE_NAME<>'documents' THEN
        IF TG_OP='UPDATE' AND OLD.document_id IS DISTINCT FROM NEW.document_id THEN
            PERFORM hash_check_branded_signing_page(OLD.document_id);
        END IF;
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER branded_signing_page_document
AFTER INSERT OR UPDATE ON documents DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION hash_guard_branded_signing_page();
CREATE CONSTRAINT TRIGGER branded_signing_page_fields
AFTER INSERT OR UPDATE OR DELETE ON document_fields DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION hash_guard_branded_signing_page();
CREATE CONSTRAINT TRIGGER branded_signing_page_branding
AFTER INSERT OR UPDATE OR DELETE ON document_branding_override DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION hash_guard_branded_signing_page();
CREATE CONSTRAINT TRIGGER branded_signing_page_recipients
AFTER INSERT OR UPDATE OR DELETE ON recipients DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION hash_guard_branded_signing_page();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM templates WHERE html_master_json->>'schema_version'='3')
       OR EXISTS(SELECT 1 FROM html_template_revisions WHERE html_master_json->>'schema_version'='3')
       OR EXISTS(SELECT 1 FROM documents WHERE html_source_json->>'schema_version'='3') THEN
        RAISE EXCEPTION 'Approved branded pages prevent destructive rollback' USING ERRCODE='23514';
    END IF;
END $$;
DROP TRIGGER branded_signing_page_recipients ON recipients;
DROP TRIGGER branded_signing_page_branding ON document_branding_override;
DROP TRIGGER branded_signing_page_fields ON document_fields;
DROP TRIGGER branded_signing_page_document ON documents;
DROP FUNCTION hash_guard_branded_signing_page();
DROP FUNCTION hash_check_branded_signing_page(UUID);
CREATE OR REPLACE FUNCTION hash_guard_html_materialization_insert() RETURNS trigger AS $$
DECLARE d documents%ROWTYPE; p html_document_materializations%ROWTYPE;
BEGIN
    SELECT * INTO STRICT d FROM documents WHERE id = NEW.document_id AND org_id = NEW.org_id FOR UPDATE;
    IF d.html_source_json IS NULL OR d.source_kind <> 'pdf' OR d.status <> 'draft' OR d.deleted_at IS NOT NULL
       OR NEW.origin_commitment IS DISTINCT FROM decode(d.html_source_json ->> 'commitment', 'hex')
       OR NEW.source_commitment IS DISTINCT FROM decode(NEW.source_json ->> 'commitment', 'hex')
       OR NEW.pdf_key IS DISTINCT FROM NEW.source_json ->> 'pdf_key'
       OR NEW.pdf_sha256 IS DISTINCT FROM decode(NEW.source_json ->> 'pdf_sha256', 'hex')
       OR NEW.pdf_version_id IS DISTINCT FROM NEW.source_json ->> 'pdf_version_id'
       OR NEW.source_json ->> 'document_id' IS DISTINCT FROM d.id::text
       OR NEW.source_json ->> 'org_id' IS DISTINCT FROM d.org_id::text
       OR EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.created_by AND u.org_id <> d.org_id) THEN
        RAISE EXCEPTION 'HTML materialization identity is inconsistent' USING ERRCODE = '23514';
    END IF;
    IF NEW.sequence = 1 THEN
        IF d.html_current_materialization_id IS NOT NULL OR NEW.source_json IS DISTINCT FROM d.html_source_json THEN
            RAISE EXCEPTION 'HTML materialization origin is inconsistent' USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT * INTO STRICT p FROM html_document_materializations WHERE id = NEW.parent_id AND document_id = d.id AND org_id = d.org_id;
        IF p.sequence + 1 <> NEW.sequence OR p.source_commitment IS DISTINCT FROM NEW.parent_commitment
           OR d.html_current_materialization_id IS DISTINCT FROM p.id THEN
            RAISE EXCEPTION 'HTML materialization parent is not current' USING ERRCODE = '23514';
        END IF;
    END IF;
    -- New text inputs never replace the original approved design/approval.
    IF (NEW.source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment'])
        IS DISTINCT FROM (d.html_source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment']) THEN
        RAISE EXCEPTION 'HTML materialization changed its approved origin' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
