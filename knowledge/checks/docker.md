# Checks — Docker exposure (`docker` section)

Read the `docker ps` listing (name / image / ports) and the privileged/network lines.
This section matters because on the prod VM the *real* internet-facing surface was a
Dockerized app, and Docker's networking interacts with the firewall in a way that
surprises people.

### Published container ports bypass the host firewall
- **id:** docker-ports-bypass-ufw
- **severity:** high (critical if the published port is a datastore — 3306/5432/6379/27017)
- **look for:** a `docker ps` line publishing a port to all interfaces (`0.0.0.0:80->80/tcp`, or `:3306->`), combined with the firewall section showing ufw active. Cross-reference the `firewall` and `listening` sections.
- **why:** Docker inserts its own DNAT rules in the `DOCKER-USER`/`FORWARD` chains, which are evaluated **before** ufw's INPUT rules. A published port is reachable from anywhere it routes **even when `ufw` shows the port as blocked** — operators routinely believe a service is firewalled when it is wide open. A published database port this way is a direct breach vector.
- **fix:** `# publish only to loopback and put a reverse proxy in front: change the mapping to '127.0.0.1:PORT:PORT' in compose/run; OR add an explicit rule in the DOCKER-USER chain: sudo iptables -I DOCKER-USER -p tcp --dport <port> ! -s <trusted-cidr> -j DROP`
- **mitre:** T1190 (Exploit Public-Facing Application)

### Privileged container
- **id:** docker-privileged-container
- **severity:** high
- **look for:** an inspect line with `privileged=true`.
- **why:** `--privileged` gives the container nearly all host capabilities and device access — a compromise of the containerized app is a straightforward escape to root on the host. It is rarely necessary.
- **fix:** `# remove --privileged; grant only the specific capabilities the workload needs (--cap-add) or specific device/mount access instead`
- **mitre:** T1611 (Escape to Host)

### Container on the host network namespace
- **id:** docker-host-network
- **severity:** medium
- **look for:** an inspect line with `netmode=host`.
- **why:** `--network host` removes container network isolation — the container shares the host's interfaces and can bind/reach ports directly, bypassing Docker's port-publishing controls and widening exposure.
- **fix:** `# use a bridge network with explicit, loopback-bound port publishing instead of --network host, unless the workload genuinely requires host networking`
- **mitre:** T1611 (Escape to Host)

### Docker group membership
- **id:** docker-group-root-equivalent
- **severity:** high
- **look for:** handled in `access.md` (`access-docker-group`) — but call it out here too when reviewing Docker: any member of the `docker` group is effectively root on the host.
- **why / fix:** see `access-docker-group`.
