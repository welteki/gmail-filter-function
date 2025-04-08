# Gmail spam detection with OpenAI.

The gmail spam detection function receives notifications for a Gmail inbox via Google Cloud Pub/Sub and uses the OpenAI API to analyze the the message and classify cold outreach messages as spam.

## Prerequisites

- An OpenFaaS installation (OpenFaaS Standard/Enterprise or OpenFaaS Edge).
- OpenFaaS GCP Pub/Sub connector deployed in the OpenFaaS cluster.
- A Google Cloud Account.
- An OpenAI account and API key.

## Running the function

1.  Set up a Google Cloud Project
    - Go to [Google Cloud Console](https://console.cloud.google.com)
    - Create or select a project
    - Enable [Pub/Sub API](https://console.cloud.google.com/apis/enableflow?apiid=pubsub.googleapis.com) and [Gmail API](https://console.cloud.google.com/apis/enableflow?apiid=gmail.googleapis.com)
    - Create a new Pub/Sub topic (e.g. gmail-notifications)
2.  Grant Gmail permissions to Publish to Pub/Sub
    - Cloud Pub/Sub requires that you grant Gmail privileges to publish notifications to your topic. To do this, you need to grant `publish` privileges to `gmail-api-push@system.gserviceaccount.com`. You can do this using the [Cloud Pub/Sub Developer Console permissions interface](https://console.cloud.google.com/project/_/cloudpubsub/topicList) or run this command with the [gcloud CLI](https://cloud.google.com/sdk/gcloud):

      ```bash
      export PROJECT_ID=""

      gcloud pubsub topics add-iam-policy-binding projects/$PROJECT_ID/topics/gmail-notifications \
        --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
        --role="roles/pubsub.publisher"
      ```

3.  Authorize with the Gmail API
    - If this has not been done already, [configure an OAuth consent screen](https://developers.google.com/workspace/gmail/api/quickstart/python#configure_the_oauth_consent_screen) for your Google Cloud Project.
    - [Get authorization credentials for a desktop application](https://developers.google.com/workspace/gmail/api/quickstart/python#authorize_credentials_for_a_desktop_application) and save them as `.secrets/credentials.json`.
    - Implement or use an existing OAuth consent flow and get a valid access token for the Gmail user. This repo includes a script `auth.py` to executes an OAuth flow that saves the access token at `.secrets/token.json`.
4.  Get an API key for the OpenAI API.
    - Login to your OpenAI account.
    - Create or select a project
    - Create a new API key and save it as `.secrets/openai-api-key`
5.  Configure the OpenFaaS GCP Pub/Sub connector
    - Update the `projectID` and `subscription` field in the `values.yaml` file for the gcp-pubsub-connector deployment and update/deploy the connector.

      Example:

        ```yaml
        projectID: "your-project-id"
        subscriptions:
          - gmail-notifications
        ```

6.  Deploy the gmail-spam-detection function
    - Add the function secrets to OpenFaaS

      ```bash
      # Gmail access token
      faas-cli secret create \
          token.json \
          --from-file .secrets/token.json

      # OpenAI API key
      faas-cli secret create \
          openai-api-key \
          --from-file .secrets/openai-api-key
      ```

    - Deploy the function

      ```bash
      faas-cli up
      ```
