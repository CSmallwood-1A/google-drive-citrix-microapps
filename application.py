from flask import Flask

from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

app = Flask(__name__)

@app.route("/")
def hello():
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url="https://googletomicroappsvault.vault.azure.net/", credential=credential)
    retrieved_secret = client.get_secret("GoogleClientSecret")
    print(retrieved_secret.name)
    print(retrieved_secret.value)
    return "Hello World!"