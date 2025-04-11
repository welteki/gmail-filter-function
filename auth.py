from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def authenticate_gmail():
    creds = None
    # Ensure .secrets directory exists
    os.makedirs('.secrets', exist_ok=True)
    
    if os.path.exists('.secrets/gmail-token'):
        creds = Credentials.from_authorized_user_file('.secrets/gmail-token', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('.secrets/credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('.secrets/gmail-token', 'w') as token:
            token.write(creds.to_json())
    return creds

def main():
    try:
        creds = authenticate_gmail()
        if creds:
            print("Successfully authenticated with Gmail!")
            print(f"Token saved to .secrets/token.json")
        else:
            print("Failed to authenticate with Gmail")
    except Exception as e:
        print(f"Error during authentication: {str(e)}")

if __name__ == "__main__":
    main()