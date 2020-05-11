from flask import Flask, render_template, redirect, request

# imports for Microsoft Azure key vault
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

# imports for google API libraries
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

import json
import requests
import uuid


app = Flask(__name__)


class ClientConfigBuilder(object):
    _DEFAULT_AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    _DEFAULT_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'

    def __init__(self, client_type=None, client_id=None, client_secret=None,
                auth_uri=_DEFAULT_AUTH_URI, token_uri=_DEFAULT_TOKEN_URI):
        self.client_type = client_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_uri = auth_uri
        self.token_uri = token_uri

    def Build(self):
        if all((self.client_type, self.client_id, self.client_secret,
                self.auth_uri, self.token_uri)):
            client_config = {
                self.client_type: {
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'auth_uri': self.auth_uri,
                    'token_uri': self.token_uri
                }
            }
        else:
            raise ValueError('Required field is missing.')
        return client_config


# get access to key vault
credential = DefaultAzureCredential()
keyVaultClient = SecretClient(vault_url="https://googletomicroappsvault.vault.azure.net/", credential=credential)

# retrieve google cloud client credentials from vault
googleClientSecret = keyVaultClient.get_secret("GoogleSecret")
googleClientID = keyVaultClient.get_secret("GoogleID")

# build the client configuration for the OAuth flow
client_config = ClientConfigBuilder(
    client_type='web',
    client_id=googleClientID.value,
    client_secret=googleClientSecret.value)

# build the google Flow object using the from ClientConfig function
flow = Flow.from_client_config(
    client_config.Build(), 
    scopes="https://www.googleapis.com/auth/drive.file",
    redirect_uri="https://google-drive-citrix-microapps.azurewebsites.net/callback/google")


@app.route("/")
def homepage():
    return render_template('homepage.html')
 
 
@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    auth_url, _ = flow.authorization_url()
    return redirect(auth_url)


@app.route("/callback/google")
def receive_auth_code():
    code = request.args['code']
    flow.fetch_token(code=code)
    service = build('drive', 'v3', credentials=flow.credentials)

    # create a folder called CitrixWorkspace
    create_body = {
        'name': 'CitrixWorkspace',
        'mimeType': 'application/vnd.google-apps.folder'
    }
    file = service.files().create(body=create_body, fields='id').execute()

    data = {
        "id": str(uuid.uuid4()),
        "type": "web_hook",
        "address": "https://google-drive-citrix-microapps.azurewebsites.net/notification"
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + flow.credentials.token
    }
    url = "https://www.googleapis.com/drive/v3/files/" + file.get('id') + "/watch"
    response = requests.post(
        url=url,
        data=json.dumps(data),
        headers=headers
    )
    return response.text


@app.route("/notification", methods=['POST'])
def reveive_notification():
    # todo - validate that this POST notification really comes from the folder
    # we subscribed to by checking the channel ID of the notification

    headers = request.headers
    resourceId = headers['X-Goog-Resource-ID']
    data = {
        "resourceId": resourceId
    }
    requests.post(
        url="https://microapps-brewery-argus.azurewebsites.net/api/webhook-listener/e5d78690-a99b-4c3c-92e9-7fed6feb0032/28410bc3-2bdb-484f-9cb6-952dc093e6dc",
        data=json.dumps(data)    
    )
    return "Received notification"


@app.route("/google459140fffb1f53cd.html")
def google_site_verification():
    return "google-site-verification: google459140fffb1f53cd.html"

