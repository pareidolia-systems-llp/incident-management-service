# Development logging stack

Spring Boot (running locally with profile `dev`) writes
`logs/incident-management.log` -> Alloy tails the file -> Loki stores logs ->
Grafana queries Loki. The application logging configuration is unchanged.
Only the fixed `application` and `environment` labels are retained. Incident
numbers, users, URLs, and exception text remain searchable log content.

## Start and stop

Run these PowerShell commands from the repository root with Docker Desktop
running in Linux-container mode:

```powershell
cd observability/dev
docker compose config
docker compose up -d
docker compose ps
docker compose logs --tail=100 grafana loki alloy
```

If this terminal cannot find Docker or `docker-credential-desktop`, open a new
terminal after installation or add the Docker Desktop `resources/bin` directory
to this terminal's PATH. For a per-user Windows installation:

```powershell
$env:PATH = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin;" + $env:PATH
```

The repository's `logs` directory must exist. The read-only `../../logs` bind
mount resolves relative to this Compose file, not the terminal's directory.
Alloy reads only `/var/log/incident-management/incident-management.log`.
Mounting the directory keeps replacement files visible after log rotation;
archived files are not collected. The mount cannot create a missing host folder.

Stop and remove the containers/network while retaining data:

```powershell
docker compose down
```

Alternatively, `docker compose stop` stops existing containers and
`docker compose start` resumes them. Containers do not automatically start with
Docker Desktop. Named volumes retain Grafana data, Loki data, and Alloy file
positions. `docker compose down -v` **deletes all three volumes**, including logs
and read positions; only use it for an intentional complete reset.

## Open Grafana Explore

- Grafana: <http://127.0.0.1:3000>
- Explore: <http://127.0.0.1:3000/explore>
- Alloy component status: <http://127.0.0.1:12345>
- Loki readiness: <http://127.0.0.1:3100/ready>

Use [Grafana's initial sign-in flow](https://grafana.com/docs/grafana/latest/setup-grafana/sign-in-to-grafana/)
and choose a new local password when prompted. Login credentials are not stored
in this repository; Grafana retains the account in its named volume. Anonymous
access is disabled so the signed-in administrator can use Explore.
All published ports bind to IPv4 loopback. Anyone with access to this computer
can query these logs; do not expose or deploy this configuration to production.

Open **Explore** from Grafana's navigation, select the provisioned **Loki**
datasource, switch to **Code**, choose **Last 15 minutes**, paste a query, and
click **Run query**. The datasource uses `http://loki:3100` inside Docker.

All Incident Management logs:

```logql
{application="incident-management-service"}
```

ERROR messages:

```logql
{application="incident-management-service", environment="dev"} |= "ERROR"
```

WARN messages:

```logql
{application="incident-management-service", environment="dev"} |= "WARN"
```

Search for an incident/ticket number (replace the example with the literal
identifier as it appears in your logs):

```logql
{application="incident-management-service", environment="dev"} |= "INC-12345"
```

These are case-sensitive text filters. Each physical line is ingested separately;
stack-trace continuation lines remain available in the unfiltered query.
Timestamps in the log text are preserved, but Loki uses ingestion time. Existing
lines therefore appear near the first stack startup time, even when their text
contains older timestamps. Alloy resumes from persisted positions on later runs.

## Verify ingestion

From this directory:

```powershell
docker compose ps
docker compose logs --tail=100 grafana loki alloy
Invoke-RestMethod http://127.0.0.1:3000/api/health
Invoke-RestMethod http://127.0.0.1:3100/ready
Invoke-RestMethod http://127.0.0.1:12345/-/ready
docker compose exec -T alloy sh -c 'test -r /var/log/incident-management/incident-management.log && wc -c /var/log/incident-management/incident-management.log'
$query = [uri]::EscapeDataString('{application="incident-management-service"}')
$result = Invoke-RestMethod "http://127.0.0.1:3100/loki/api/v1/query_range?query=$query&since=1h&limit=5"
$result.data.result | ConvertTo-Json -Depth 6
```

A nonempty result with the application label and log lines verifies ingestion.
On first startup, a nonempty existing file is sufficient: Spring Boot does not
need restarting or even to be running. Keep it running to verify newly appended
logs through normal application use. No application calls or restarts are part
of starting this stack. Allow roughly a minute for initial Loki readiness; Alloy
retries while Loki starts. If no results appear, inspect Alloy component status,
file permissions, and container logs, then widen Grafana's time range. On Windows,
Docker Desktop must have permission to read the repository folder.

Loki runs in monolithic mode with TSDB/filesystem storage and one replica. Logs
expire after seven days through the compactor (deletion is asynchronous, not a
hard disk quota). Memory limits total 1.5 GiB across the three containers; actual
use varies and Docker Desktop/WSL2 also uses memory. Container diagnostic logs
rotate at 10 MiB with three files per container.

## Validation on 2026-10-14

`docker compose config` passed and all three containers started successfully.
Grafana health/login, Loki readiness, and Alloy readiness returned HTTP 200.
Docker inspection confirmed the log bind mount is read-only. Alloy could read
the existing 5,179-byte file, and Loki returned 34 lines matching that file.
The series API confirmed exactly the `application` and `environment` labels.
The datasource was provisioned automatically. Spring Boot was not restarted or
changed. Browser sign-in and a visual Explore check remain manual.

Loki briefly logged `empty ring` during initialization and subsequently became
ready and served the logs. Grafana emitted migration/alerting registration
warnings during startup; health checks passed. There were no Alloy startup
errors. Grafana's standard login is used because this version does not support
anonymous Editor access.

## References

- [Loki filesystem configuration](https://grafana.com/docs/loki/latest/configure/examples/configuration-examples/)
- [Alloy file source and saved positions](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.file/)
- [Grafana initial sign-in](https://grafana.com/docs/grafana/latest/setup-grafana/sign-in-to-grafana/)
