# domain-watcher

A minimal Docker container that polls WHOIS for one or more domain names and
sends a notification whenever the registration status changes.

Supported TLDs out of the box: **.nl** (SIDN WHOIS server pre-configured).
Any other TLD falls back to the system `whois` binary, which works for most
common TLDs (.com, .net, .org, .de, …).

---

## Quick start

```bash
# 1. Clone / copy these files into a directory
# 2. Edit docker-compose.yml — fill in DOMAINS and at least one notifier
# 3. Start
docker compose up -d

# Watch live logs
docker compose logs -f
```

---

## Configuration (environment variables)

| Variable | Required | Default | Description |
|---|---|---|---|
| `DOMAINS` | ✅ | — | Comma-separated list of domains to watch |
| `CHECK_INTERVAL` | | `3600` | Seconds between WHOIS checks |
| `NOTIFY_WEBHOOK` | | — | Slack / Discord / generic webhook URL |
| `NOTIFY_EMAIL_TO` | | — | Recipient address |
| `NOTIFY_EMAIL_FROM` | | — | Sender address |
| `SMTP_HOST` | | — | SMTP server hostname |
| `SMTP_PORT` | | `587` | SMTP port (STARTTLS) |
| `SMTP_USER` | | — | SMTP username |
| `SMTP_PASS` | | — | SMTP password |

Set variables directly in `docker-compose.yml` or use a `.env` file alongside it.

---

## Notification channels

### Slack
Create an [Incoming Webhook](https://api.slack.com/messaging/webhooks) and set:
```
NOTIFY_WEBHOOK: "https://hooks.slack.com/services/T.../B.../..."
```

### Discord
Create a [webhook in a channel](https://support.discord.com/hc/en-us/articles/228383668) and set:
```
NOTIFY_WEBHOOK: "https://discord.com/api/webhooks/..."
```

### Generic HTTP POST
Any URL receives a JSON POST body `{"subject": "...", "body": "..."}`.

### Email (SMTP with STARTTLS)
Gmail example (use an [App Password](https://support.google.com/accounts/answer/185833)):
```
NOTIFY_EMAIL_TO: "you@example.com"
NOTIFY_EMAIL_FROM: "sender@gmail.com"
SMTP_HOST: "smtp.gmail.com"
SMTP_PORT: "587"
SMTP_USER: "sender@gmail.com"
SMTP_PASS: "your-app-password"
```

---

## State & persistence

State is stored in `/data/state.json` inside the container, mapped to
`./data/` on the host. Delete this file to reset all baselines (the next
check will treat everything as "first seen" and won't fire spurious alerts).

---

## Adding more TLDs

Edit the `whois_server` dict in `checker.py`:

```python
whois_server = {
    "nl": "whois.domain-registry.nl",
    "be": "whois.dns.be",
    "de": "whois.denic.de",
}
```

---

## What triggers a notification?

A SHA-256 fingerprint is computed from the parsed WHOIS fields
(status, registrar, name servers, dates, registered flag).
Any change in that fingerprint fires a notification with a before/after diff.
