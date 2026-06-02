from datetime import datetime
import json
import os

severity_rules = {
    "successful_login": "LOW",
    "failed_login": "MEDIUM",
    "password_change": "MEDIUM",
    "new_user_created": "HIGH",
    "admin_access": "HIGH",
    "account_locked": " MEDIUM",
    "privilege_escalation": " HIGH",
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
        "event_type": "use_user_created",
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

os.makedirs("logs", exist_ok=True)

with open("logs/security_event.json", "w") as file:
    json.dump(events, file, indent=2)

print(f"Saved {len(events)} security events.")