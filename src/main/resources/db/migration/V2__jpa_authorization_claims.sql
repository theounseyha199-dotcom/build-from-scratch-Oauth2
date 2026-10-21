-- The JPA authorization service stores ID token claims separately from token metadata.
ALTER TABLE oauth2_authorization ADD COLUMN oidc_id_token_claims text;
