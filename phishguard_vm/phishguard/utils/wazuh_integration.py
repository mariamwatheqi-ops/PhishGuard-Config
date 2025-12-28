import requests
import base64
import json

WAZUH_API_URL = "https://172.31.25.216:55000"  #  manager private IP
WAZUH_USER = "wazuh"
WAZUH_PASSWORD = "wazuh"  
VERIFY_SSL = False  # using self-signed cert
# PhishGuard EC2 agent ID shown in Wazuh UI (Agents tab)
WAZUH_AGENT_ID = "001"
def get_wazuh_token():
    """
    Authenticate to Wazuh API and return a JWT token.
    """
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    credentials = {
        "username": WAZUH_USER,
        "password": WAZUH_PASSWORD
    }

    try:
        response = requests.post(url, json=credentials, verify=VERIFY_SSL)
        response.raise_for_status()
        data = response.json()
        return data["data"]["token"]
    except Exception as e:
        print(f"[WAZUH] Error getting token: {e}")
        return None


def send_phishguard_event(agent_id: str, message: str, extra: dict = None):
    """
    Send a custom PhishGuard event to Wazuh.
    - agent_id: e.g. '001' ( PhishGuard EC2 agent)
    - message: short text log to send
    - extra: optional dict with more JSON fields
    """
    token = get_wazuh_token()
    if not token:
        print("[WAZUH] No token, cannot send event")
        return False

    url = f"{WAZUH_API_URL}/logs"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "agent": {
            "id": agent_id
        },
        "log": {
            "program": "phishguard",
            "message": message
        }
    }

    # Attaching extra fields if provided (they will appear in data section)
    if extra:
        payload["log"]["extra"] = extra

    try:
        resp = requests.post(url, headers=headers, json=payload, verify=VERIFY_SSL)
        print("[WAZUH] Send log status:", resp.status_code, resp.text[:200])
        return resp.status_code in (200, 201)
    except Exception as e:
        print(f"[WAZUH] Error sending event: {e}")
        return False
