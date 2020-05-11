_REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'

class ClientConfigBuilder(object):
    _DEFAULT_AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    _DEFAULT_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
    CLIENT_TYPE_WEB = 'web'
    CLIENT_TYPE_INSTALLED_APP = 'installed'

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