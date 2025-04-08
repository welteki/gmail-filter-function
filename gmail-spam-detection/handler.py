import os.path
import json
import base64
import openai
import logging
from openai import OpenAI
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CLASSIFY_PROMPT = """
Analyze the following email and determine if it is a cold outreach email.

Return your answer in the following JSON format:
{
  "is_cold_outreach": [true | false],
  "confidence": [float between 0 and 1],
  "reasoning": "Short explanation",
  "from": "Sender address of the email",
  "subject": "The email subject"
}

Email:
"""
COLD_OUTREACH_LABEL = "Cold Outreach"

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def read_secret(name):
    with open(f"/var/openfaas/secrets/{name}") as f:
        return f.read().strip()

openai_api_key = read_secret("openai-api-key")
openAIClient = OpenAI(api_key=openai_api_key)

def handle(event, context):
    logger.info("Starting email processing")
    try:
        eventData = json.loads(event.body)
        logger.info(f"Received event data: {eventData}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse pubsub event: {str(e)}")
        return { "statusCode": 404, "body": "Failed to parse pubsub event" }
    
    email = eventData["emailAddress"]
    historyId = eventData["historyId"]
    logger.info(f"Processing email: {email}, historyId: {historyId}")

    try:
        gmail_service = authenticate_gmail()
        logger.info("Successfully authenticated with Gmail")
    except Exception as e:
        logger.error(f"Failed to authenticate with Gmail: {str(e)}")
        return { "statusCode": 500, "body": "Failed to authenticate with Gmail" }

    try:
        changed_message_ids = get_changed_messages(gmail_service, start_history_id=historyId)
        logger.info(f"Found {len(changed_message_ids)} changed messages")
    except Exception as e:
        logger.error(f"Failed to get changed messages: {str(e)}")
        return { "statusCode": 500, "body": "Failed to get changed messages" }

    try:
        cold_outreach_label_id = get_or_create_label(gmail_service, COLD_OUTREACH_LABEL)
        logger.info(f"Got cold outreach label ID: {cold_outreach_label_id}")
    except Exception as e:
        logger.error(f"Failed to get/create cold outreach label: {str(e)}")
        return { "statusCode": 500, "body": "Failed to get/create cold outreach label" }

    results = []
    for msg_id in changed_message_ids:
        logger.info(f"Processing message {msg_id}")
        try:
            content = get_email_content(gmail_service, msg_id)
            logger.info(f"Got email content from {content['from']} with subject '{content['subject']}'")
        except Exception as e:
            logger.error(f"Failed to get email content for message {msg_id}: {str(e)}")
            results.append({
                "message_id": msg_id,
                "error": "Failed to get email content"
            })
            continue

        try:
            response = classify_email_content(CLASSIFY_PROMPT, content)
            logger.info(f"Got classification response: {response}")
        except Exception as e:
            logger.error(f"Failed to classify email {msg_id}: {str(e)}")
            results.append({
                "message_id": msg_id,
                "error": "Failed to classify email"
            })
            continue

        try:
            result = json.loads(response)
            logger.info(f"Classification result for email from {result['from']} with subject '{result['subject']}':")
            logger.info(f"Cold outreach: {result['is_cold_outreach']} (confidence: {result['confidence']})")
            logger.info(f"Reasoning: {result['reasoning']}")
            
            if result['is_cold_outreach']:
                add_label(gmail_service, cold_outreach_label_id, msg_id)
                logger.info(f"Added {COLD_OUTREACH_LABEL} label to message {msg_id}")
            
            results.append({
                "message_id": msg_id,
                "classification": result
            })
        except json.JSONDecodeError:
            logger.error(f"OpenAI did not return valid JSON: {response}")
            results.append({
                "message_id": msg_id,
                "error": "Failed to parse classification result"
            })

    logger.info("Completed processing all messages")
    return {
        "statusCode": 202,
        "body": json.dumps({"results": results})
    }


def authenticate_gmail():
    creds = None
    if os.path.exists('/var/openfaas/secrets/token.json'):
        creds = Credentials.from_authorized_user_file('/var/openfaas/secrets/token.json', SCOPES)
    if not creds:
        raise Exception("Failed to load credentials")
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
    
    return build('gmail', 'v1', credentials=creds)

def get_changed_messages(service, user_id='me', start_history_id=None):
    response = service.users().history().list(
        userId=user_id,
        startHistoryId=start_history_id,
        historyTypes=['messageAdded']
    ).execute()

    message_ids = []
    if 'history' in response:
        for history in response['history']:
            if 'messages' in history:
                for msg in history['messagesAdded']:
                    message = msg['message']
                    if 'SPAM' in message['labelIds']:
                        continue
                    else: 
                        message_ids.append(message['id'])

    return message_ids

def add_label(service, label, message_id, user_id="me"):
    service.users().messages().modify(
        userId='me',
        id=message_id,
        body={
            'addLabelIds': [label],
            'removeLabelIds': []
        }
    ).execute()

def get_email_content(service, message_id, user_id='me'):
    msg = service.users().messages().get(userId=user_id, id=message_id, format='full').execute()
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
    return response.choices[0].message.content

def get_or_create_label(service, label_name, user_id='me'):
    # Step 1: Get existing labels
    response = service.users().labels().list(userId=user_id).execute()
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

    new_label = service.users().labels().create(userId=user_id, body=label_body).execute()
    return new_label['id']