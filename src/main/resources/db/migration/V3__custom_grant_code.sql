CREATE TABLE custom_grant_code (
    code_hash varchar(64) PRIMARY KEY,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used boolean NOT NULL DEFAULT false
);
