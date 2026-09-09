# domain-watcher

A small, containerized daemon that polls `whois` for a list of domains on a schedule, detects changes (registration status, registrar, name servers, expiry date, DNSSEC, etc.), and notifies you via webhook (Slack/Discord/generic) and/or email when something changes.

Domains are automatically grouped by TLD and checked in parallel — each TLD group runs on its own independent schedule, so throttling requests to one slow/rate-limited registry never delays checks for any other TLD.

## Features

- **Change detection, not just uptime** — fingerprints the parsed whois record (status, registrar, name servers, DNSSEC, dates) and only notifies when something actually changes.
- **Handles both flat and block-style whois formats**, including the SIDN (`.nl`) multi-line registrar/abuse-contact style.
- **Per-TLD parallel scheduling** — each TLD gets its own worker thread and its own `CHECK_INTERVAL` cycle, so N domains across N TLDs don't serialize into an N × interval wait.
- **Configurable per-TLD throttling** between whois queries to the same registry, to stay polite to rate-limited whois servers.
- **Notifications** via Slack, Discord, generic JSON webhook, and/or SMTP email — auto-detected from the webhook URL.
- **Persistent state** across restarts (`/data/state.json`), written atomically so a crash or `kill -9` mid-write can't corrupt it.
- **Graceful shutdown** on `SIGTERM`/`SIGINT` — finishes in-flight work and exits promptly instead of hanging around for the rest of the interval.
- **Self-healing workers** — if a TLD worker thread dies unexpectedly, the main process restarts it rather than silently losing coverage for that TLD.

## Quick start

```bash
docker run -d \
  --name domain-watcher \
  -e DOMAINS="example.com,example.nl,example.org" \
  -e CHECK_INTERVAL=3600 \
  -e NOTIFY_WEBHOOK="https://hooks.slack.com/services/XXX/YYY/ZZZ" \
  -v domain-watcher-data:/data \
  wobwobrt/domain-watcher:latest
```

That's it — logs will show each TLD group starting up, and you'll get a "First check" notification for every domain the first time it's seen, then a "Change detected" notification whenever something in its whois record changes.

### docker-compose

```yaml
services:
  domain-watcher:
    image: wobwobrt/domain-watcher:latest
    container_name: domain-watcher
    restart: unless-stopped
    environment:
      DOMAINS: "example.com,example.nl,example.org"
      CHECK_INTERVAL: "3600"
      TLD_THROTTLE_SECONDS: "2"
      NOTIFY_WEBHOOK: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
      NOTIFY_EMAIL_TO: "you@example.com"
      NOTIFY_EMAIL_FROM: "domain-watcher@example.com"
      SMTP_HOST: "smtp.example.com"
      SMTP_PORT: "587"
      SMTP_USER: "smtp-user"
      SMTP_PASS: "smtp-pass"
    volumes:
      - domain-watcher-data:/data

volumes:
  domain-watcher-data:
```

## Configuration

All configuration is via environment variables — nothing to mount or edit inside the container besides the state volume.

| Variable                | Default                  | Description                                                                 |
|--------------------------|---------------------------|-------------------------------------------------------------------------------|
| `DOMAINS`                | `example.com`             | Comma-separated list of domains to watch.                                    |
| `CHECK_INTERVAL`         | `300`                     | Seconds between whois checks, per TLD group.                                 |
| `TLD_THROTTLE_SECONDS`   | `2`                       | Delay between consecutive whois queries *within* the same TLD group.         |
| `NOTIFY_WEBHOOK`         | *(unset)*                 | Webhook URL. Slack (`hooks.slack.com`) and Discord (`discord.com`) URLs are auto-formatted; anything else gets a generic `{subject, body}` JSON POST. |
| `NOTIFY_EMAIL_TO`        | `notify@example.com`      | Recipient address for email notifications.                                   |
| `NOTIFY_EMAIL_FROM`      | `checker@example.com`     | From address for email notifications.                                        |
| `SMTP_HOST`              | `smtp.example.com`        | SMTP server host.                                                             |
| `SMTP_PORT`              | `587`                     | SMTP port. `465` uses implicit TLS (`SMTP_SSL`); anything else uses STARTTLS. |
| `SMTP_USER` / `SMTP_PASS`| *(unset)*                 | SMTP credentials, if your server requires auth.                              |

Leave `NOTIFY_WEBHOOK` empty to disable webhook notifications, or leave `NOTIFY_EMAIL_TO`/`SMTP_HOST` unset to disable email — you can use either, both, or neither.

## State & persistence

State (the last-seen whois fingerprint and parsed fields for every domain) is kept in `/data/state.json` inside the container. Mount a volume at `/data` if you want history to survive container restarts/upgrades — otherwise every restart is treated as a fresh "first check" for every domain, which will re-trigger notifications.

## Signals

The container responds to `SIGTERM` (what `docker stop` sends) and `SIGINT` by finishing any in-flight whois checks and shutting down promptly, so it's safe to restart or redeploy without waiting out `CHECK_INTERVAL`.

## Building locally

```bash
git clone https://github.com/WobwobRt/domain-watcher.git
cd domain-watcher
docker build -t domain-watcher .
docker run --rm -e DOMAINS="example.com" domain-watcher
```

Or run it directly with Python 3.11+ (needs the `whois` binary on `PATH`):

```bash
pip install -r requirements.txt   # if applicable
DOMAINS="example.com" python3 watcher.py
```

## Contributing

Issues and PRs welcome — in particular, additional TLD-specific whois parsers (following the pattern used for `.nl`/SIDN in `parse_status()`) are always useful.

## License

<add your license here — e.g. MIT>
