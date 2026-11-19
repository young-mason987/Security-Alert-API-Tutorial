
import os
import requests

API_URL = "http://127.0.0.1:8000/alerts"

API_KEY = os.environ["SECURITY_API_KEY"]

headers = {
    "X-API-Key": API_KEY
}

# Simulated security events
login_events = [
    {"device": "LAPTOP-001", "failed_attempts": 2},
    {"device": "LAPTOP-002", "failed_attempts": 8},
    {"device": "LAPTOP-003", "failed_attempts": 1},
    {"device": "LAPTOP-004", "failed_attempts": 12}
]

THRESHOLD = 5

for event in login_events:

    if event["failed_attempts"] >= THRESHOLD:

        print(
            f"Suspicious activity detected on {event['device']}"
        )

        alert = {
            "device": event["device"],
            "description": (
                f"{event['failed_attempts']} failed login "
                "attempts detected"
            ),
            "severity": "high"
        }

        try:
            response = requests.post(
                API_URL,
                json=alert,
                headers=headers,
                timeout=10
            )

            response.raise_for_status()

            print("Alert created:", response.json())

        except requests.exceptions.RequestException as error:
            print("Failed to create alert:", error)

    else:
        print(
            f"Normal activity on {event['device']}"
        )
