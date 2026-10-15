# Production observability: manual VM runbook

These files target the supplied Ubuntu 26.04.1 x86_64 VM architecture. They do
not deploy anything. All Linux commands below are for an administrator on the
VM unless explicitly marked as workstation commands. The Windows repository
does not provide access to the VM's filesystem. Development configuration is
separate and unchanged; do not start this Compose project on the development
machine (its ports overlap with development).

Native `incident-management.service` -> journald -> native Alloy -> Docker Loki
-> Docker Grafana. Browser Faro -> HTTPS Nginx `/faro/collect` -> native Alloy
`127.0.0.1:12347/collect` -> the same Loki. Only Grafana and Loki run in Docker.
There is no Docker socket mount, Prometheus, Session Replay, Cloud integration,
or trace storage. Application services have no dependency on observability.
Do not edit the existing backend/frontend deployment, application service,
OAuth routes, database, or `/opt/pareidolia/scripts/deploy-incident.sh`.

## Rollout order (do not skip the verification gates)

1. Start Loki and Grafana.
2. Install/configure native Alloy.
3. Verify Spring Boot journald logs reach Loki.
4. Add Nginx `/faro/collect` proxy.
5. Verify Faro collector through HTTPS.
6. Only then enable Faro in the production frontend.
7. Verify frontend telemetry in Grafana.

Observability failure must never prevent the Incident Management application
from running. Do not add systemd dependencies to the application or hook these
steps into its deployment. Receiver failures must remain non-blocking in the
later frontend task. Stop the rollout on a failed gate; keep the app running.

## 1. Start Loki and Grafana

Manually place this directory on the VM, preserving its relative file layout.
The examples assume the repository is available at the supplied application
working directory; adjust only the initial `cd` if copied elsewhere.

```bash
cd /opt/pareidolia/incident-management-service/observability/prod
umask 077
cp -n .env.example .env
chmod 600 .env
nano .env
```

Set `GRAFANA_ADMIN_USER` and a unique strong `GRAFANA_ADMIN_PASSWORD` from your
password manager. The example password is empty so startup fails until set.
Use single quotes around dotenv values containing `$` or `#`; do not put real
secrets on the shell command line or commit `.env`. The local `.gitignore`
excludes `.env` and its variants while allowing `.env.example`. Check with
`git check-ignore .env`. Keep the directory accessible only to operators.

```bash
# Syntax/interpolation validation without printing the resolved password:
docker compose config --quiet
# Plain `docker compose config` also works, but prints credentials: do not share its output.
docker compose up -d
docker compose ps
docker compose logs --tail=100 loki grafana
curl -fsS http://127.0.0.1:3100/ready
curl -I http://127.0.0.1:3000
curl -fsS http://127.0.0.1:3000/api/health
```

Wait for Loki readiness (initial startup may briefly return 503). Grafana may
redirect to login; its health API should report database `ok`. Docker commands
require an authorized Docker operator (or `sudo`); Docker access is effectively
root access. Do not grant Docker access to Alloy.

Grafana `13.2.4` and Loki `3.7.0` use official pinned images. Review release and
security updates before rollout and during maintenance. Grafana has anonymous
access and signup disabled. The admin environment values initialize a new
database; changing `.env` later does not reset an existing account's password.
Rotate existing passwords through Grafana's supported account administration.

Compose creates these volumes **on deployment**, not during configuration checks:

- `incident-management-observability-prod_grafana-data`: Grafana database/settings.
- `incident-management-observability-prod_loki-data`: chunks, index, WAL and compactor state.

Loki uses one monolithic process, TSDB v13/filesystem and replication factor 1.
Retention is 14 days, with asynchronous compactor deletion; this is not a disk
quota or a backup. Grafana is capped at 512 MiB/1 CPU, Loki at 1 GiB/1 CPU, with
no reservations. These are starting limits for the 7.2 GiB VM, not measured
production sizing. Watch memory/OOM restarts, query latency and disk growth:

```bash
docker stats --no-stream
docker system df
df -h
```

Container diagnostic logs rotate at 10 MiB x 3 files each. Monitor total VM
disk use, including native journald and Alloy state; retention cannot guarantee
that 77 GiB remains sufficient under abuse or unexpectedly high log volume.
Keep application resource headroom and reduce collection/load before increasing
limits. Back up the volumes securely if historical logs/dashboards are required.

## 2. Install and configure native Alloy

Use Grafana's official APT repository. Run these manually on Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates wget gpg
sudo install -d -m 0755 /etc/apt/keyrings
sudo wget -O /etc/apt/keyrings/grafana.asc https://apt.grafana.com/gpg-full.key
sudo chmod 644 /etc/apt/keyrings/grafana.asc
echo 'deb [signed-by=/etc/apt/keyrings/grafana.asc] https://apt.grafana.com stable main' | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update
apt-cache policy alloy
sudo apt-get install -y alloy
sudo systemctl stop alloy
alloy --version
```

This configuration is validated against Alloy 1.20.1. The repository may offer
a newer version: review it and validate with the installed binary before start.
If Alloy is already installed, back up its existing configuration and review
any existing pipelines rather than blindly replacing them.

```bash
sudo usermod -aG adm,systemd-journal alloy
id alloy
sudo -u alloy journalctl _SYSTEMD_UNIT=incident-management.service -n 20 --no-pager
sudo install -o root -g alloy -m 0640 alloy-config.alloy /etc/alloy/config.alloy
sudo -u alloy /usr/bin/alloy validate /etc/alloy/config.alloy
sudoedit /etc/default/alloy
```

In `/etc/default/alloy`, set these entries, preserving unrelated package settings:

```ini
CONFIG_FILE="/etc/alloy/config.alloy"
CUSTOM_ARGS="--server.http.listen-addr=127.0.0.1:12345 --disable-reporting"
```

Keep the default Alloy engine. The package uses `/var/lib/alloy/data` for
persisted state/cursors; keep that path writable by `alloy` and do not clear it
on updates. Confirm the installed unit runs as `alloy` and uses this storage path:

```bash
sudo systemctl cat alloy
sudo systemctl show alloy -p User -p Group -p ExecStart
sudo systemctl enable alloy
sudo systemctl restart alloy
sudo systemctl status alloy --no-pager
sudo journalctl -u alloy -n 100 --no-pager
curl -fsS http://127.0.0.1:12345/-/ready
```

Restart applies supplementary journal groups. Do not run Alloy as root. Group
membership allows reading broader host logs, but the configured reader uses
`matches = "_SYSTEMD_UNIT=incident-management.service"` to collect only the app.
No explicit journal path is set so native Alloy can discover persistent and
volatile journals. `format_as_json = false` forwards the journal MESSAGE body,
including stack-trace text; no regex rewrites or severity filtering are applied.
Separate journal entries remain separate log entries. Only `application` and
`environment` survive backend relabeling. Initial catch-up is limited to 24 hours;
journal rotation, long outages or lost cursor state can cause gaps or replay.

Journal membership alone is not proof of ingestion: a reader can be healthy
while receiving nothing. If the `sudo -u alloy journalctl` command cannot read
the app logs, resolve VM journal permissions before proceeding; do not change
application execution privileges or open journal files to everyone.

## 3. Verify backend ingestion and private listeners

```bash
sudo journalctl -u incident-management -n 20 --no-pager
curl -fsSG http://127.0.0.1:3100/loki/api/v1/query_range \
  --data-urlencode 'query={application="incident-management-service", environment="prod"}' \
  --data-urlencode 'since=1h' --data-urlencode 'limit=20'
curl -fsS http://127.0.0.1:12345/metrics | grep loki_source_journal_target_lines_total
sudo ss -ltnp
docker compose port grafana 3000
docker compose port loki 3100
docker compose ps
```

Compare returned messages with the application journal and verify a naturally
occurring new application log appears. Do not restart the app just to make logs.
Widen the query to `since=24h` if the app has been idle. Verify all four host
ports bind only to loopback: Grafana 3000, Loki 3100, Alloy UI 12345, Faro 12347.
None may bind to `0.0.0.0`, `[::]`, or a public/private network interface.
Docker may implement publishing through NAT without a userspace listener, so
also check Compose ports and Docker inspection, not `ss` alone:

```bash
docker inspect "$(docker compose ps -q grafana)" --format '{{json .HostConfig.PortBindings}}'
docker inspect "$(docker compose ps -q loki)" --format '{{json .HostConfig.PortBindings}}'
```

From another machine, verify connection attempts to `<vm-host>` ports 3000,
3100, 12345 and 12347 fail (for example `nc -vz -w 3 <vm-host> 3000`, repeated
for each port). Keep these ports closed in VM/cloud firewalls; do not rely on
UFW alone for Docker-published services. Use a supported, patched Docker Engine.

For Grafana, run on the administrator workstation:

```bash
ssh -N -L 127.0.0.1:3000:127.0.0.1:3000 <vm-user>@<vm-host>
```

Browse <http://127.0.0.1:3000>, sign in with the production `.env` credentials,
and select **Explore -> Loki -> Code**. If local development already occupies
3000, use local port 3001 in the tunnel and browse port 3001 instead. Loki is
provisioned at `http://loki:3100` inside Docker; native Alloy writes via host
loopback. Do not add a public Grafana route.

```logql
{application="incident-management-service", environment="prod"}
```

## 4. Add the exact Nginx collector route

Manually back up and edit the existing HTTPS application server block for
`incident.pareidolia.in`. Add only this exact-match location. Preserve all
existing `/api/`, `/oauth2/`, `/login/`, static frontend and TLS configuration.

```nginx
location = /faro/collect {
    client_max_body_size 1m;
    proxy_pass http://127.0.0.1:12347/collect;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Connection "";
    proxy_set_header Authorization "";
    proxy_set_header Cookie "";
    proxy_set_header X-Forwarded-For "";
    proxy_set_header X-Real-IP "";
    proxy_set_header Forwarded "";
    proxy_connect_timeout 2s;
    proxy_send_timeout 5s;
    proxy_read_timeout 5s;
    access_log off;
}
```

The URI on `proxy_pass` maps `/faro/collect` to `/collect`. This does not expose
the Alloy UI or other receiver routes. Nginx passes Origin and content headers
through; Alloy owns CORS, so do not add wildcard CORS headers in Nginx. The
block strips app cookies/auth headers from the upstream request and suppresses
collector access logging. Review any inherited VM proxy/auth directives during
integration; the complete Nginx configuration has not been supplied or tested.

```bash
sudo nginx -t
# Only after the test succeeds:
sudo systemctl reload nginx
```

## 5. Verify the HTTPS collector before frontend enablement

```bash
curl -i -X OPTIONS https://incident.pareidolia.in/faro/collect \
  -H 'Origin: https://incident.pareidolia.in' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type'
```

Expect a 2xx preflight and exactly the production origin in
`Access-Control-Allow-Origin`. Repeat with `Origin: https://example.invalid`:
it must not receive an allow-origin header. This is a CORS check, not proof of
authentication or delivery. A safe synthetic log can verify the full route:

```bash
curl --fail-with-body -i https://incident.pareidolia.in/faro/collect \
  -H 'Origin: https://incident.pareidolia.in' \
  -H 'Content-Type: application/json' \
  --data "{\"meta\":{\"app\":{\"name\":\"incident-management-ui\",\"environment\":\"prod\"}},\"logs\":[{\"message\":\"Production Faro rollout verification\",\"level\":\"info\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}]}"
sudo journalctl -u alloy -n 100 --no-pager
```

Expect HTTP 202 and then find that synthetic message using the frontend query
below. Do not send real user data as a test. POST errors, 413 (payload limit),
429 (rate limit), and 502/504 (upstream unavailable) need investigation before
frontend rollout. Test existing app routes still work after the Nginx change.

## 6–7. Enable frontend separately, then verify

Only after gates 1–5 succeed, the separate frontend task can enable Faro at
build time with collector `https://incident.pareidolia.in/faro/collect`.
This task does not change frontend code/build/deployment or its privacy filters.
Open the production app, exercise a normal instrumented action, and confirm
successful collector POSTs without CORS errors in browser DevTools. Query in
Grafana Explore (Loki, Last 15 minutes):

```logql
{application="incident-management-ui", environment="prod"}
```

Faro adds only these two fixed labels, disables connection metadata and source
map downloading, and rate limits globally to 10 requests/second with burst 20.
Payload size is limited to 1 MiB at Alloy and Nginx. No browser-derived values
are promoted to Loki labels. Source maps are disabled to avoid requests to
untrusted client-supplied URLs. No Session Replay or trace destination is enabled.

## Risks, maintenance and rollback

- CORS is not authentication: arbitrary clients can forge the Origin header.
  The public collector can accept fabricated telemetry and consume resources.
  Global rate/payload limits reduce exposure but are not a complete DoS defense.
- `include_metadata = false` does not scrub telemetry bodies. URLs, user/session
  identifiers, exception text, and log messages may still contain personal data
  or secrets. Preserve frontend filtering, review sample payloads before rollout,
  restrict Grafana/backup access, and never log tokens or credentials.
- `.env` and container environment values are visible to privileged VM/Docker
  administrators. Protect the file, avoid sharing resolved Compose output, and
  remember backups may contain both logs and Grafana credentials/settings.
- Loki has no authentication and trusts local access and the isolated Compose
  network. Loopback publishing is mandatory; no Nginx route may expose Loki.
- Journal groups grant broad read access; collection is filtered but a compromised
  Alloy process could read other journal entries. Keep Alloy patched and non-root.
- Logs are best-effort telemetry, not an audit store: finite retry buffers,
  restarts, journal rotation and long outages can lose logs. The application
  must continue normally when observability is unavailable.

To stop observability, run `sudo systemctl stop alloy` and `docker compose down`
from this directory. Volumes remain; do not use `down -v` unless deliberately
erasing all observability data. If Faro causes issues, disable it in the separate
frontend rollout and remove only the added Nginx location after `nginx -t`, then
reload Nginx. Backend application service and deployment remain unchanged.
Back up Alloy config/state and Docker data before upgrades; test restores.

## Validation scope

On 2026-10-15, local `docker compose config --quiet` passed with explicitly
non-secret validation environment values. An empty password was rejected as
intended. Disposable, network-disabled containers ran Alloy 1.20.1 `validate`
and Loki 3.7.0 `-verify-config=true` successfully, mounting only this repository
directory read-only, with no published ports. Compose's YAML parser also parsed
the Loki and datasource documents as extension values. Git whitespace checks,
new-file trailing-whitespace checks and `.env` ignore checks passed. Development
files had no diff. No production volumes were created by these checks.

Local syntax validation does not establish native journal permissions, Ubuntu
package compatibility, Nginx integration, TLS/CORS runtime behavior, resource
sizing, or production log ingestion. All runtime gates above remain VM tasks.
No VM paths were inspected from Windows and no production services were started.

## Official references

- [Alloy Ubuntu installation](https://grafana.com/docs/alloy/latest/set-up/install/linux/)
- [Native service configuration](https://grafana.com/docs/alloy/latest/configure/linux/)
- [Journal matching and permissions](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.journal/)
- [Faro receiver](https://grafana.com/docs/alloy/latest/reference/components/faro/faro.receiver/)
- [Loki filesystem configuration](https://grafana.com/docs/loki/latest/configure/examples/configuration-examples/)
