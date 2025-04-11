import os.path
import json
import base64
import logging
from openai import OpenAI
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def read_secret(name):
    with open(f"/var/openfaas/secrets/{name}") as f:
        return f.read().strip()

def read_prompt():
    with open(os.path.join(os.path.dirname(__file__), 'static', 'prompt.txt'), 'r') as f:
        return f.read().strip()
    
def watch(gmail_client, project_id, topic):
    request = {
        'labelIds': ['INBOX'],
        'topicName': f'projects/{project_id}/topics/{topic}',
        'labelFilterBehavior': 'INCLUDE'
    }
    
    response = gmail_client.users().watch(userId='me', body=request).execute()
    return response.get('historyId')

def get_gmail_client():
    # Scopes to use for authenticating with Gmail.
    scopes = ['https://www.googleapis.com/auth/gmail.modify']

    creds = None
    if os.path.exists('/var/openfaas/secrets/token.json'):
        creds = Credentials.from_authorized_user_file('/var/openfaas/secrets/token.json', scopes)
    if not creds:
        raise Exception("Failed to load credentials")
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
    
    return build('gmail', 'v1', credentials=creds)

# Configuration

project_id = os.getenv('project_id')
# Pub/Sub topic to send inbox notifications to.
notification_topic = os.getenv('notification_topic')

# Prompt to use for classifying emails.
classify_prompt = read_prompt()
# Label to add to cold outreach emails.
cold_outreach_label = os.getenv('cold_outreach_label')

# OpenAI API key.
openai_api_key = read_secret("openai-api-key")
openAIClient = OpenAI(api_key=openai_api_key)

# State
lastHistoryId = None

def init():
    global lastHistoryId
    gmail_client = get_gmail_client()
    lastHistoryId = watch(gmail_client, project_id, notification_topic)

init()

def handle(event, context):    
    if event.path == '/watch' or event.headers.get('X-Connector') == 'cron-connector':
        # Handle watch requests from the cron-connector.
        return handle_watch(event, context)
    else:
        # Handle notification requests from the pubsub-connector.
        return handle_notification(event, context)

def handle_watch(event, context):
    try:
        gmail_client = get_gmail_client()
        watch(gmail_client, project_id, notification_topic)

        logger.info("Successfully set up Gmail watch on INBOX with topic: %s", notification_topic)
        return { "statusCode": 202 }
    except Exception as e:
        logger.error("Failed to set up Gmail watch: %s", str(e))
        return { "statusCode": 500, "body": "Failed to watch Gmail inbox" }

def handle_notification(event, context):
    global lastHistoryId

    try:
        eventData = parse_pubsub_event(event)

        email = eventData["emailAddress"]
        historyId = eventData["historyId"]
        logger.info(f"Received notification: email: {email}, historyId: {historyId}")
    except Exception as e:
        return { "statusCode": 404, "body": "Invalid pubsub event" }

    try:
        gmail_client = get_gmail_client()
        # Ensure the label for tagging messages exits.
        label_id = get_or_create_label(gmail_client, cold_outreach_label)
        # Get all messages that have been added to the INBOX since the last notification.
        msg_ids = get_changed_messages(gmail_client, start_history_id=lastHistoryId)
    except Exception as e:
        logger.error(f"Failed to handle notification: {e}")
        return { "statusCode": 500, "body": "Failed to handle notification" }

    for msg_id in msg_ids:
        try:
            # Get the content of the email using the Gmail API.
            msg_content = get_email_content(gmail_client, msg_id)
            # Call the OpenAI API to classify the email.
            classification = classify_email_content(classify_prompt, msg_content)
            logger.info(f"Classification response for message {msg_id}: {classification}")

            # If the email is classified as cold outreach, add a label to the message.
            if classification['is_cold_outreach']:
                add_label(gmail_client, label_id, msg_id)
        except Exception as e:
            logger.warning(f"Failed to process message {msg_id}: {e}")
            continue
    
    # Update the history ID to indicate we have processed messages up to this point.
    lastHistoryId = historyId

    return { "statusCode": 202 }

def parse_pubsub_event(event):
    try:
        # Try to load the body as JSON
        eventData = json.loads(event.body)

        # Ensure the parsed data is a dictionary
        if not isinstance(eventData, dict):
            raise RuntimeError("Parsed JSON is not a dictionary.")
        
        # Get required fields from the event data
        email = eventData.get("emailAddress")
        historyId = eventData.get("historyId")

        # Validate required fields
        if not email:
            raise RuntimeError("emailAddress is required")
        if not historyId:
            raise RuntimeError("historyId is required")

        return eventData
    except Exception as e:
        raise RuntimeError(f"Failed to parse pubsub event: {e}") from e

def get_changed_messages(gmail_client, user_id='me', start_history_id=None):
    response = gmail_client.users().history().list(
        userId=user_id,
        startHistoryId=start_history_id,
        labelId='INBOX', # Only return messages in the INBOX
        historyTypes=['messageAdded']
    ).execute()

    message_ids = []
    if 'history' in response:
        for history in response['history']:
            if 'messages' in history:
                for msg in history['messagesAdded']:
                    message = msg['message']
                    message_ids.append(message['id'])
                    
    return message_ids

def get_email_content(gmail_client, message_id, user_id='me'):
    msg = gmail_client.users().messages().get(userId=user_id, id=message_id, format='full').execute()
    payload = msg.get('payload', {})
    headers = payload.get('headers', [])

    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
    from_email = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')

    parts = payload.get('parts', [])
    body = ''
    if parts:
        for part in parts:
            if part.get('mimeType') == 'text/plain':
                data = part['body']['data']
                body = base64.urlsafe_b64decode(data.encode('UTF-8')).decode('utf-8')
                break
    else:
        data = payload['body'].get('data')
        if data:
            body = base64.urlsafe_b64decode(data.encode('UTF-8')).decode('utf-8')

    return {
        'from': from_email,
        'subject': subject,
        'body': body
    }

def add_label(gmail_client, label, message_id, user_id="me"):
    gmail_client.users().messages().modify(
        userId='me',
        id=message_id,
        body={
            'addLabelIds': [label],
            'removeLabelIds': []
        }
    ).execute()

def get_or_create_label(gmail_client, label_name, user_id='me'):
    # Step 1: Get existing labels
    response = gmail_client.users().labels().list(userId=user_id).execute()
    labels = response.get('labels', [])

    # Step 2: Check if label already exists
    for label in labels:
        if label['name'].lower() == label_name.lower():
            return label['id']

    # Step 3: Create the label if it doesn't exist
    label_body = {
        'name': label_name, 
        'labelListVisibility': 'labelShow',       # show in label list
        'messageListVisibility': 'show'           # show in message list
    }

    new_label = gmail_client.users().labels().create(userId=user_id, body=label_body).execute()
    return new_label['id']

def classify_email_content(prompt, content):
    full_prompt = f"{prompt}\n\nFrom: {content['from']}\nSubject: {content['subject']}\nBody:\n{content['body']}"
    response = openAIClient.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are an assistant that classifies emails. Always respond with JSON."},
            {"role": "user", "content": full_prompt}
        ],
        temperature=0.2,  # Low randomness for consistent output
        max_tokens=300
    )

    try:
        return json.loads(response.choices[0].message.content)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON returned by model: {e}") from e
