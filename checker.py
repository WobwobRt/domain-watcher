#!/usr/bin/env python3
import os
import json
import subprocess
import hashlib
import smtplib
import logging
import time
import re
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

STATE_FILE = Path("/data/state.json")
DOMAINS = [d.strip() for d in os.environ.get("DOMAINS", "").split(",") if d.strip()]
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "3600"))

# Notification config
NOTIFY_WEBHOOK = os.environ.get("NOTIFY_WEBHOOK", "")       # Slack / Discord / generic webhook
NOTIFY_EMAIL_TO = os.environ.get("NOTIFY_EMAIL_TO", "")
NOTIFY_EMAIL_FROM = os.environ.get("NOTIFY_EMAIL_FROM", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")


def whois(domain: str) -> str:
    """Run whois and return raw output."""
    tld = domain.rsplit(".", 1)[-1].lower()
    whois_server = {
        "nl": "whois.domain-registry.nl",
    }.get(tld)

    cmd = ["whois"]
    if whois_server:
        cmd += ["-h", whois_server]
    cmd.append(domain)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        log.warning("whois timed out for %s", domain)
        return ""
    except FileNotFoundError:
        log.error("whois binary not found")
        return ""


def parse_status(raw: str) -> dict:
    """Extract key fields from whois output."""
    fields = {}

    patterns = {
        "status": r"(?:Status|Domain Status)\s*:\s*(.+)",
        "registrar": r"Registrar\s*:\s*(.+)",
        "created": r"(?:Creation Date|Created|registered)\s*:\s*(.+)",
        "expires": r"(?:Registry Expiry Date|Expiry Date|expires)\s*:\s*(.+)",
        "name_servers": r"Name Server\s*:\s*(.+)",
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw, re.IGNORECASE)
        if matches:
            fields[key] = [m.strip() for m in matches] if len(matches) > 1 else matches[0].strip()

    # Detect if domain is free / not registered
    free_indicators = [
        "no object found",
        "not found",
        "no match",
        "available",
        "is free",
    ]
    raw_lower = raw.lower()
    fields["registered"] = not any(ind in raw_lower for ind in free_indicators)

    return fields


def fingerprint(data: dict) -> str:
    serialised = json.dumps(data, sort_keys=True)
    return hashlib.sha256(serialised.encode()).hexdigest()


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def save_state(state: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def notify(domain: str, old: dict, new: dict):
    subject = f"[domain-watcher] Change detected: {domain}"
    body_lines = [
        f"Domain: {domain}",
        f"Checked at: {datetime.utcnow().isoformat()}Z",
        "",
        "=== Previous state ===",
        json.dumps(old.get("parsed", {}), indent=2),
        "",
        "=== New state ===",
        json.dumps(new, indent=2),
    ]
    body = "\n".join(body_lines)
    log.info("CHANGE DETECTED for %s — sending notifications", domain)

    if NOTIFY_WEBHOOK:
        _webhook(subject, body)
    if NOTIFY_EMAIL_TO and SMTP_HOST:
        _email(subject, body)


def _webhook(subject: str, body: str):
    import urllib.request
    import urllib.error

    # Auto-detect Slack vs Discord vs generic
    payload_str = ""
    if "hooks.slack.com" in NOTIFY_WEBHOOK:
        payload = {"text": f"*{subject}*\n```{body}```"}
        payload_str = json.dumps(payload)
    elif "discord.com" in NOTIFY_WEBHOOK:
        payload = {"content": f"**{subject}**\n```{body}```"}
        payload_str = json.dumps(payload)
    else:
        # Generic JSON POST
        payload = {"subject": subject, "body": body}
        payload_str = json.dumps(payload)

    req = urllib.request.Request(
        NOTIFY_WEBHOOK,
        data=payload_str.encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        log.info("Webhook notification sent")
    except urllib.error.URLError as e:
        log.error("Webhook failed: %s", e)


def _email(subject: str, body: str):
    msg = MIMEMultipart()
    msg["From"] = NOTIFY_EMAIL_FROM
    msg["To"] = NOTIFY_EMAIL_TO
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(NOTIFY_EMAIL_FROM, NOTIFY_EMAIL_TO, msg.as_string())
        log.info("Email notification sent to %s", NOTIFY_EMAIL_TO)
    except Exception as e:
        log.error("Email failed: %s", e)


def check_domain(domain: str, state: dict):
    log.info("Checking %s …", domain)
    raw = whois(domain)
    if not raw:
        log.warning("Empty whois response for %s, skipping", domain)
        return

    parsed = parse_status(raw)
    fp = fingerprint(parsed)
    prev = state.get(domain, {})

    if prev.get("fingerprint") != fp:
        notify(domain, prev, parsed)
        state[domain] = {
            "fingerprint": fp,
            "parsed": parsed,
            "last_changed": datetime.utcnow().isoformat() + "Z",
        }
    else:
        log.info("No change for %s (status: %s)", domain, parsed.get("status", "?"))

    state[domain]["last_checked"] = datetime.utcnow().isoformat() + "Z"


def main():
    if not DOMAINS:
        log.error("No domains configured. Set the DOMAINS env var (comma-separated).")
        return

    log.info("Starting domain-watcher — domains: %s, interval: %ss", DOMAINS, CHECK_INTERVAL)

    while True:
        state = load_state()
        for domain in DOMAINS:
            try:
                check_domain(domain, state)
            except Exception as e:
                log.error("Error checking %s: %s", domain, e)
        save_state(state)
        log.info("Next check in %s seconds", CHECK_INTERVAL)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
