import base64

def encode_basic_auth(username: str, password: str) -> str:
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    return f"Basic {encoded_credentials}"

# Example usage
username = "62vXKqR"
password = "c8a4e8d78240495d98a930db386b7bb8"
print(encode_basic_auth(username, password))
