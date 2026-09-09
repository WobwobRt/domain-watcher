#!/usr/bin/env python3
import os
import json
import subprocess
import hashlib
import smtplib
import logging
import time
import re
import datetime
import threading
import signal
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

STATE_FILE = Path("/data/state.json")
DOMAINS = [d.strip() for d in os.environ.get("DOMAINS", "example.com").split(",") if d.strip()]
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "300"))

# Delay between successive whois queries to the *same* TLD (rate-limit friendly).
# Applied per TLD-worker thread; different TLDs run concurrently and are unaffected
# by each other's throttling.
TLD_THROTTLE = float(os.environ.get("TLD_THROTTLE_SECONDS", "2"))

# Shared in-memory state + lock. All TLD worker threads read/write through this
# lock so the state file never gets corrupted by concurrent writes, and no
# worker ever clobbers another worker's domains when saving.
STATE_LOCK = threading.Lock()

# Set by the SIGTERM/SIGINT handler. Worker threads check this instead of
# sleeping blindly, so a `docker stop` / `kill` shuts things down promptly
# rather than waiting out whatever's left of the current interval.
SHUTDOWN = threading.Event()


def _handle_signal(signum, frame):
    log.info("Received %s — shutting down…", signal.Signals(signum).name)
    SHUTDOWN.set()

# Notification config
NOTIFY_WEBHOOK = os.environ.get("NOTIFY_WEBHOOK", "")       # Slack / Discord / generic webhook
NOTIFY_EMAIL_TO = os.environ.get("NOTIFY_EMAIL_TO", "notify@example.com")
NOTIFY_EMAIL_FROM = os.environ.get("NOTIFY_EMAIL_FROM", "checker@example.com")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.example.com")
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
    """
    Parse whois output into structured fields.

    Handles the SIDN (.nl) format which uses indented multi-line blocks:

        Domain name: example.nl
        Status:      active
        Registrar:
           Hostnet B.V.
           De Ruijterkade 6
           ...
        Abuse Contact:
           +31.207500800
           abuse@hostnet.nl
        DNSSEC:      yes
        Domain nameservers:
           ns01.hostnet.nl
           ns02.hostnet.nl
        Creation Date: 1996-10-03
        Updated Date:  2025-07-02
        Record maintained by: SIDN BV

    Also handles the flat key: value style used by most other TLDs.
    """
    lines = raw.splitlines()
    fields: dict = {}

    # --- detect availability first ---
    raw_lower = raw.lower()
    free_indicators = [
        "no object found", "not found", "no match",
        "available", "is free", "status: free",
    ]
    fields["registered"] = not any(ind in raw_lower for ind in free_indicators)

    # --- single-value flat patterns (key: value on one line) ---
    flat_patterns = {
        "domain":          r"^Domain(?:\s+name)?\s*:\s*(.+)",
        "status":          r"^(?:Status|Domain\s+Status)\s*:\s*(.+)",
        "dnssec":          r"^DNSSEC\s*:\s*(.+)",
        "created":         r"^(?:Creation\s+Date|Created\s+Date?|registered)\s*:\s*(.+)",
        "updated":         r"^(?:Updated\s+Date?|Last\s+Modified)\s*:\s*(.+)",
        "expires":         r"^(?:Registry\s+Expiry\s+Date|Expiry\s+Date|paid-till|expires)\s*:\s*(.+)",
        "maintained_by":   r"^Record\s+maintained\s+by\s*:\s*(.+)",
    }
    for key, pattern in flat_patterns.items():
        for line in lines:
            m = re.match(pattern, line.strip(), re.IGNORECASE)
            if m:
                fields[key] = m.group(1).strip()
                break

    # --- multi-line indented blocks (SIDN style) ---
    # A block starts with a header line ending in ":" (no value on same line),
    # followed by indented continuation lines.
    block_headers = {
        "registrar":       r"^Registrar\s*:$",
        "abuse_contact":   r"^Abuse\s+Contact\s*:$",
        "name_servers":    r"^Domain\s+nameservers?\s*:$",
    }

    i = 0
    while i < len(lines):
        line = lines[i]
        for key, pattern in block_headers.items():
            if re.match(pattern, line.strip(), re.IGNORECASE):
                block = []
                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    # Indented lines belong to the block
                    if next_line.startswith("   ") or next_line.startswith("\t"):
                        val = next_line.strip()
                        if val:
                            block.append(val)
                        j += 1
                    else:
                        break
                if block:
                    fields[key] = block
                i = j - 1
                break
        i += 1

    # --- fallback: flat name-server lines (non-SIDN TLDs) ---
    if "name_servers" not in fields:
        ns_matches = re.findall(r"^Name\s+Server\s*:\s*(.+)", raw, re.IGNORECASE | re.MULTILINE)
        if ns_matches:
            fields["name_servers"] = [ns.strip().lower() for ns in ns_matches]

    # --- fallback: flat registrar line ---
    if "registrar" not in fields:
        m = re.search(r"^Registrar\s*:\s*(.+)", raw, re.IGNORECASE | re.MULTILINE)
        if m:
            fields["registrar"] = [m.group(1).strip()]

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
    # Write to a temp file and atomically swap it into place, so a crash or
    # kill mid-write can never leave state.json truncated/corrupt (which
    # would otherwise be silently discarded wholesale by load_state()).
    tmp_path = STATE_FILE.with_suffix(STATE_FILE.suffix + ".tmp")
    tmp_path.write_text(json.dumps(state, indent=2))
    os.replace(tmp_path, STATE_FILE)


def _fmt_field(value) -> str:
    """Format a parsed field value for display."""
    if isinstance(value, list):
        return "\n".join(f"   {v}" for v in value)
    return f"   {value}"


def _fmt_parsed(parsed: dict) -> str:
    """Render a parsed whois dict in a readable block."""
    order = [
        "domain", "status", "registered", "dnssec",
        "registrar", "abuse_contact", "name_servers",
        "created", "updated", "expires", "maintained_by",
    ]
    labels = {
        "domain":         "Domain name",
        "status":         "Status",
        "registered":     "Registered",
        "dnssec":         "DNSSEC",
        "registrar":      "Registrar",
        "abuse_contact":  "Abuse Contact",
        "name_servers":   "Name servers",
        "created":        "Creation Date",
        "updated":        "Updated Date",
        "expires":        "Expiry Date",
        "maintained_by":  "Maintained by",
    }
    lines = []
    seen = set()
    for key in order + [k for k in parsed if k not in order]:
        if key not in parsed or key in seen:
            continue
        seen.add(key)
        label = labels.get(key, key.replace("_", " ").title())
        val = parsed[key]
        if isinstance(val, list):
            lines.append(f"{label}:")
            for v in val:
                lines.append(f"   {v}")
        elif isinstance(val, bool):
            lines.append(f"{label}:  {'yes' if val else 'no'}")
        else:
            lines.append(f"{label}:  {val}")
    return "\n".join(lines)


def _diff_summary(old: dict, new: dict) -> str:
    """Summarise what actually changed between two parsed dicts."""
    all_keys = set(old) | set(new)
    changes = []
    for key in sorted(all_keys):
        o, n = old.get(key), new.get(key)
        if o != n:
            label = key.replace("_", " ").title()
            o_str = ", ".join(o) if isinstance(o, list) else str(o)
            n_str = ", ".join(n) if isinstance(n, list) else str(n)
            changes.append(f"  {label}:\n    was: {o_str}\n    now: {n_str}")
    return "\n".join(changes) if changes else "  (fingerprint changed but no field diff found)"


def notify(domain: str, old: dict, new: dict):
    first_seen = not old  # no previous state at all
    subject = (
        f"[domain-watcher] First check: {domain}"
        if first_seen
        else f"[domain-watcher] Change detected: {domain}"
    )

    old_parsed = old.get("parsed", {})
    body_lines = [
        f"Domain:     {domain}",
        f"Checked at: {datetime.datetime.now(datetime.UTC).isoformat()}Z",
        "",
    ]

    if first_seen:
        body_lines += ["=== Initial state ===", _fmt_parsed(new)]
    else:
        body_lines += [
            "=== What changed ===",
            _diff_summary(old_parsed, new),
            "",
            "=== Previous state ===",
            _fmt_parsed(old_parsed),
            "",
            "=== New state ===",
            _fmt_parsed(new),
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
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(NOTIFY_EMAIL_FROM, NOTIFY_EMAIL_TO, msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                if SMTP_USER:
                    server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(NOTIFY_EMAIL_FROM, NOTIFY_EMAIL_TO, msg.as_string())
            log.info("Email notification sent to %s", NOTIFY_EMAIL_TO)
    except Exception as e:
        log.error("Email failed: %s", e)


def check_domain(domain: str, prev: dict):
    """
    Run whois for a single domain and compare against its previous state.

    Deliberately takes/returns plain dicts rather than touching shared state
    itself — the slow part (the actual whois network call) happens with no
    lock held, so it can't block other TLD worker threads. Returns the new
    state entry to store for this domain, or None if the check failed and
    nothing should be updated.
    """
    log.info("Checking %s …", domain)
    raw = whois(domain)
    if not raw:
        log.warning("Empty whois response for %s, skipping", domain)
        return None

    parsed = parse_status(raw)
    fp = fingerprint(parsed)
    now = datetime.datetime.now(datetime.UTC).isoformat() + "Z"

    if prev.get("fingerprint") != fp:
        notify(domain, prev, parsed)
        return {
            "fingerprint": fp,
            "parsed": parsed,
            "last_changed": now,
            "last_checked": now,
        }
    else:
        log.info("No change for %s (status: %s)", domain, parsed.get("status", "?"))
        entry = dict(prev)
        entry["last_checked"] = now
        return entry


def group_by_tld(domains):
    groups = defaultdict(list)
    for d in domains:
        tld = d.rsplit(".", 1)[-1].lower()
        groups[tld].append(d)
    return groups


def tld_worker(tld: str, domains: list, state: dict):
    """
    Owns the check/sleep cycle for a single TLD. Runs forever in its own
    thread. Its throttle delay only affects the domains in *this* TLD group —
    it never adds to any other TLD's schedule, so N TLDs no longer means the
    effective interval grows to roughly N * CHECK_INTERVAL.
    """
    log.info(
        "[.%s] worker starting — %d domain(s), throttle %ss, interval %ss",
        tld, len(domains), TLD_THROTTLE, CHECK_INTERVAL,
    )
    while not SHUTDOWN.is_set():
        cycle_start = time.monotonic()
        try:
            for i, domain in enumerate(domains):
                if SHUTDOWN.is_set():
                    break

                with STATE_LOCK:
                    prev = state.get(domain, {})
                try:
                    new_entry = check_domain(domain, prev)
                except Exception as e:
                    log.error("Error checking %s: %s", domain, e)
                    new_entry = None

                if new_entry is not None:
                    with STATE_LOCK:
                        state[domain] = new_entry
                        save_state(state)

                # Only throttle between domains *within* this TLD group.
                # Waiting on the event (rather than time.sleep) lets a
                # shutdown signal interrupt the throttle immediately.
                if i < len(domains) - 1:
                    SHUTDOWN.wait(timeout=TLD_THROTTLE)
        except Exception:
            # Catch-all so an unexpected failure (e.g. disk full during
            # save_state, or a bug in a new TLD parser) can't silently kill
            # this thread outright. The main-thread supervisor will restart
            # it too if it ever does exit, but we'd rather just keep this
            # thread alive and try again next cycle.
            log.exception("[.%s] worker hit an unexpected error this cycle", tld)

        if SHUTDOWN.is_set():
            break

        elapsed = time.monotonic() - cycle_start
        sleep_time = max(0.0, CHECK_INTERVAL - elapsed)
        log.info(
            "[.%s] cycle finished in %.1fs — next check in %.0fs",
            tld, elapsed, sleep_time,
        )
        SHUTDOWN.wait(timeout=sleep_time)

    log.info("[.%s] worker stopping", tld)


def spawn_worker(tld: str, domains: list, state: dict) -> threading.Thread:
    t = threading.Thread(
        target=tld_worker,
        args=(tld, domains, state),
        name=f"tld-{tld}",
        daemon=True,
    )
    t.start()
    return t


def main():
    if not DOMAINS:
        log.error("No domains configured. Set the DOMAINS env var (comma-separated).")
        return

    # SIGTERM is what Docker/Kubernetes send on stop/restart; SIGINT covers
    # Ctrl+C during local runs. Both trigger the same graceful shutdown path.
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    state = load_state()
    groups = group_by_tld(DOMAINS)

    log.info(
        "Starting domain-watcher — %d TLD group(s) across %d domain(s), interval: %ss",
        len(groups), len(DOMAINS), CHECK_INTERVAL,
    )

    workers = {tld: spawn_worker(tld, domains, state) for tld, domains in groups.items()}

    # Supervisor loop: as long as we haven't been asked to shut down, watch
    # for any worker thread that has died unexpectedly and restart it, so a
    # single crashed TLD worker doesn't quietly stop monitoring that TLD for
    # the rest of the process's life.
    while not SHUTDOWN.is_set():
        for tld, domains in groups.items():
            if not workers[tld].is_alive() and not SHUTDOWN.is_set():
                log.error("[.%s] worker exited unexpectedly — restarting", tld)
                workers[tld] = spawn_worker(tld, domains, state)
        SHUTDOWN.wait(timeout=1.0)

    log.info("Waiting for workers to finish their current cycle…")
    for t in workers.values():
        t.join(timeout=CHECK_INTERVAL + 30)
    log.info("Domain-watcher stopped.")


if __name__ == "__main__":
    main()
