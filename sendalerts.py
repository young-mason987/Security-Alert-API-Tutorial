import requests
import os

api_key = os.environ["SECURITY_API_KEY"]

headers = {
    "X-API-Key": api_key
}

url = "http://127.0.0.1:8000/alerts"

security_alert = {
    "device": "Firewall-1",
    "description": "Multiple failed login attempts detected.",
    "severity": "high"
}

try: 

    response = requests.post(
        url,
        json=security_alert,
        headers=headers,
        timeout=10
    )

    response.raise_for_status()  # Raise an error for bad responses (4xx and 5xx)

    print("Alert sent successfully!")
    print("HTTP Status:", response.status_code)
    print("Response:", response.json())

except requests.exceptions.RequestException as error:
    print("Failed to successfully send the alert.", error)
