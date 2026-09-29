import re
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter

LOG_FILE = Path("logs/auth.log")


def parse_log_line(line):
    pattern = (
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>\w+)"
        r"\[\d+\]:\s+"
        r"(?P<message>.*)$"
    )

    match = re.match(pattern, line)

    if not match:
        return None

    event = match.groupdict()

    event["datetime"] = datetime.strptime(
        f"2026 {event['timestamp']}",
        "%Y %b %d %H:%M:%S"
    )

    return event


def parse_authentication_event(event):
    message = event["message"]

    patterns = [
        (
            r"Failed password for (?P<username>\S+) from (?P<ip>\S+)",
            "failed_login",
        ),
        (
            r"Accepted (?:password|publickey) for (?P<username>\S+) from (?P<ip>\S+)",
            "successful_login",
        ),
        (
            r"Invalid user (?P<username>\S+) from (?P<ip>\S+)",
            "invalid_user",
        ),
    ]

    for pattern, event_type in patterns:
        match = re.search(pattern, message)

        if match:
            event["event"] = event_type
            event.update(match.groupdict())
            return event

    return None

def detect_failed_login_bursts(events, threshold=5, window_minutes=5):
    findings = []
    window = timedelta(minutes=window_minutes)

    failed_events = [
        event for event in events
        if event.get("event") == "failed_login"
    ]

    failed_events.sort(key=lambda event: event["datetime"])

    i = 0

    while i < len(failed_events):
        event = failed_events[i]
        window_start = event["datetime"] - window

        events_in_window = [
            candidate
            for candidate in failed_events[i:]
            if candidate["ip"] == event["ip"]
            and window_start <= candidate["datetime"] <= event["datetime"] + window
        ]

        if len(events_in_window) >= threshold:
            usernames = Counter(
                candidate["username"]
                for candidate in events_in_window
            )

            first_seen = events_in_window[0]["datetime"]
            last_seen = events_in_window[-1]["datetime"]

            findings.append({
                "type": "potential_brute_force",
                "ip": event["ip"],
                "failed_attempts": len(events_in_window),
                "window_minutes": window_minutes,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "targeted_usernames": dict(usernames),
            })

            i += len(events_in_window)
        else:
            i += 1

    return findings


def print_finding(finding):
    print("\n[MEDIUM] Potential brute-force pattern")
    print(f"Source IP: {finding['ip']}")

    usernames = ", ".join(
        f"{username} ({count})"
        for username, count in finding["targeted_usernames"].items()
    )

    print(f"Target account(s): {usernames}")
    print(f"Failed attempts: {finding['failed_attempts']}")
    print(f"First seen: {finding['first_seen'].strftime('%b %d %H:%M:%S')}")
    print(f"Last seen: {finding['last_seen'].strftime('%b %d %H:%M:%S')}")
    print(f"Detection window: {finding['window_minutes']} minutes")
    print("Assessment: Pattern is consistent with repeated password guessing.")


def main():
    events = []

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            event = parse_log_line(line)

            if event is None:
                print("Could not parse line:", line)
                continue

            auth_event = parse_authentication_event(event)

            if auth_event:
                events.append(auth_event)
            else:
                print("Unrecognized event:", event)

    findings = detect_failed_login_bursts(events)

    print("\n=== Security Findings ===")

    for finding in findings:
        print_finding(finding)


if __name__ == "__main__":
    main()
