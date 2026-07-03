# Checks — listening ports / services (`listening` section of the snapshot)

Read `ss`/`netstat` output. Columns include local address:port and the owning
process. A local address of `0.0.0.0`/`*`/`::` means "all interfaces" (exposed);
`127.0.0.1`/`::1` means localhost-only (not externally reachable).

### Plaintext / legacy service exposed
- **id:** ports-plaintext-service
- **severity:** high
- **look for:** listeners on all interfaces for plaintext/legacy ports — telnet `23`, FTP `21`, rsh `514`, or HTTP-only admin panels.
- **why:** Plaintext protocols leak credentials on the wire and are heavily targeted; they should not be internet-facing.
- **fix:** `# stop/replace the service or bind it to localhost; confirm with: ss -tulpn | grep -E ':21|:23|:514'`

### Database / cache exposed on all interfaces
- **id:** ports-database-exposed
- **severity:** high
- **look for:** all-interface listeners on `3306` (MySQL), `5432` (Postgres), `27017` (Mongo), `6379` (Redis), `9200` (Elasticsearch), `11211` (memcached).
- **why:** Datastores bound to `0.0.0.0` are a top breach vector (often unauthenticated or weakly authenticated). Combined with no firewall this is *critical*.
- **fix:** `# bind the service to 127.0.0.1 (e.g. Redis 'bind 127.0.0.1', MySQL 'bind-address=127.0.0.1') and/or firewall the port`

### Unexpected service on all interfaces
- **id:** ports-unexpected-listener
- **severity:** medium
- **look for:** an all-interface listener whose process/port you did not expect for this host's role.
- **why:** Unknown exposed services are unmanaged attack surface; each one is something to identify, justify, or shut down.
- **fix:** `# identify the owner and decide: ss -tulpn ; then bind to localhost or firewall if not needed externally`
