print("Yoroi initialized")

from datetime import datetime
import json
import os

event = {
    "event_type": "failed_login",
    "username": "admin",
    "source_ip": "192.168.1.25",
    "severity": "medium",
    "timestamp": datetime.utcnow().isoformat()
}

os.makedirs("logs", exist_ok=True)

with open("logs/security_event.json", "w") as file:
    json.dump(event, file, indent=2)

print("Security event saved to logs/security_event.json")