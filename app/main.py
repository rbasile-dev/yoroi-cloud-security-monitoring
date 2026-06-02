from datetime import datetime
import json
import os

print("Yoroi Security Monitoring System")
print("--------------------------------")

severity_rules = {
    "successful_login": "LOW",
    "failed_login": "MEDIUM",
    "password_change": "MEDIUM",
    "new_user_created": "HIGH",
    "admin_access": "HIGH",
    "account_locked": "MEDIUM",
    "privilege_escalation": "HIGH",
}

events = [
    {
        "event_type": "failed_login",
        "username": "admin",
        "source_ip": "192.168.1.25",
        "timestamp": datetime.utcnow().isoformat()
    },
    {
        "event_type": "privilege_escalation",
        "username": "admin",
        "source_ip": "192.168.1.25",
        "timestamp": datetime.utcnow().isoformat()
    },
    {
        "event_type": "successful_login",
        "username": "jsmith",
        "source_ip": "192.168.1.30",
        "timestamp": datetime.utcnow().isoformat()
    },
    {
        "event_type": "password_change",
        "username": "admin",
        "source_ip": "192.168.1.25",
        "timestamp": datetime.utcnow().isoformat()
    },
    {
        "event_type": "new_user_created",
        "username": "security_admin",
        "source_ip": "192.168.1.10",
        "timestamp": datetime.utcnow().isoformat()
    },
    {
        "event_type": "admin_access",
        "username": "admin",
        "source_ip": "192.168.1.25",
        "timestamp": datetime.utcnow().isoformat()
    },
    {
        "event_type": "account_locked",
        "username": "jdoe",
        "source_ip": "192.168.1.50",
        "timestamp": datetime.utcnow().isoformat()
    }
]

for event in events:
    event["severity"] = severity_rules.get(
        event["event_type"],
        "UNKNOWN"
    )

high_count = 0
medium_count = 0
low_count= 0

for event in events:
    if event["severity"] == "HIGH":
        high_count += 1
    elif event["severity"] == "MEDIUM":
        medium_count += 1
    elif event["severity"] == "LOW":
        low_count += 1


os.makedirs("logs", exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
filename = f"logs/security_events_{timestamp}.json"

with open(filename, "w") as file:
    json.dump(events, file, indent=2)

print()
print("Analysis Summary")
print("----------------")
print(f"Total Events: {len(events)}")
print(f"High Severity: {high_count}")
print(f"Medium Severity: {medium_count}")
print(f"Low Severity: {low_count}")

if high_count > 0:
    print()
    print("WARNING: High severity events detected!")

print()
print(f"Log File: {filename}")
print(f"Saved {len(events)} security events to {filename}")
