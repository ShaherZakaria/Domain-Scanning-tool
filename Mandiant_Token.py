import base64
import requests
url = "https://api.intelligence.mandiant.com/token"
api_key = "api_key"
api_secret = "api_secret"
auth_token_bytes = f"{api_key}:{api_secret}".encode("ascii")
base64_auth_token_bytes = base64.b64encode(auth_token_bytes)
base64_auth_token = base64_auth_token_bytes.decode("ascii")
headers = {
    "Authorization": f"Basic {base64_auth_token}",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
    "X-App-Name": "insert app name"
}
params = {"grant_type": "client_credentials"}
access_token = requests.post(url=url, headers=headers, data=params)
Mandiant_Token=access_token.json().get("access_token")
print(access_token.json().get("access_token"))