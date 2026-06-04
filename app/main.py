from datetime import datetime
import json
import os

def count_log_files():
    os.makedirs("logs", exist_ok=True)
    files = os.listdir("logs")

    print("\nPrevious Log Files")
    print("--------------------")

    for file in files:
        print(file)

    return len(files)

severity_rules = {
    "successful_login": "LOW",
    "failed_login": "MEDIUM",
    "password_change": "MEDIUM",
    "new_user_created": "HIGH",
    "admin_access": "HIGH",
    "account_locked": "MEDIUM",
    "privilege_escalation": "HIGH",
}

def generate_events():
    return [
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

def add_severity(events):
    for event in events:
        event["severity"] = severity_rules.get(
            event["event_type"],
            "UNKNOWN"
        )

def analyze_events(events):
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

    return high_count, medium_count, low_count

def save_events(events):
    os.makedirs("logs", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"logs/security_events_{timestamp}.json"

    with open(filename, "w") as file:
        json.dump(events, file, indent=2)
        
    return filename

def analyze_historical_logs():
    os.makedirs("logs", exist_ok=True)

    total_events = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    files = os.listdir("logs")

    for filename in files:

        if not filename.endswith(".json"):
            continue

        filepath = os.path.join("logs", filename)

        with open(filepath, "r") as file:
            events = json.load(file)

        total_events += len(events)

        for event in events:

            if event.get("severity") == "HIGH":
                high_count += 1

            elif event.get("severity") == "MEDIUM":
                medium_count += 1

            elif event.get("severity") == "LOW":
                low_count += 1

    return total_events, high_count, medium_count, low_count



def print_summary(events, high_count, medium_count, low_count, filename):
    print("Yoroi Security Monitoring System")
    print("--------------------------------")
    print()
    print("Analysis Summary")
    print("----------------")
    print(f"Total Events: {len(events)}")
    print(f"High Severity: {high_count}")
    print(f"Medium Severity: {medium_count}")
    print(f"Low Severity: {low_count}")

    if high_count >= 3:
        print()
        print("CRITICAL ALERT: Multiple high severity events detected!")

    elif high_count > 0:
        print()
        print("WARNING: High severity events detected!")

    print()
    print(f"Log File: {filename}")
    print(f"Saved {len(events)} security events to {filename}")

def main():
    log_count = count_log_files()

    historical_total, historical_high, historical_medium, historical_low = analyze_historical_logs()

    print()
    print(f"Previous Log Files Found: {log_count}")

    print()
    print(f"Historical Analysis")
    print("----------------------------------")
    print(f"Total Events Recorded: {historical_total}")
    print(f"Historical HIGH: {historical_high}")
    print(f"Historical MEDIUM: {historical_medium}")
    print(f"Historical LOW: {historical_low}")
    print()

    events = generate_events()
    add_severity(events)

    high_count, medium_count, low_count = analyze_events(events)
    filename = save_events(events)
    print_summary(events, high_count, medium_count, low_count, filename)

if __name__ == "__main__":
    main()
    