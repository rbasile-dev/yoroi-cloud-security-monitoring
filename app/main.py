from datetime import datetime
import json
import os

events = [
    {
        "event_type": "failed_login",
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

os.makedirs("logs", exist_ok=True)

with open("logs/security_event.json", "w") as file:
    json.dump(events, file, indent=2)

print(f"Saved {len(events)} security events.")