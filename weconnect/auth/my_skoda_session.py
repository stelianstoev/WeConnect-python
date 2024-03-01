from datetime import datetime
from typing import Dict, Optional, Match
import jwt

import re
import json
import logging
import requests

from urllib.parse import parse_qsl, urlsplit

from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from oauthlib.common import to_unicode
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2 import is_secure_transport

from requests.models import CaseInsensitiveDict
from weconnect.auth.openid_session import AccessType


from weconnect.auth.vw_web_session import VWWebSession
from weconnect.errors import APICompatibilityError, AuthentificationError, RetrievalError, TemporaryAuthentificationError


LOG = logging.getLogger("weconnect")

# Headers used for fetching tokens for different clients
TOKEN_HEADERS = {
    'connect': {
        'Accept': 'application/json',
        'X-Platform': 'Android',
        'Accept-Charset': 'UTF-8',
        'Content-Type': 'application/json',
        'Connection': 'keep-alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'OneConnect/000000157 CFNetwork/1485 Darwin/23.1.0',
    },
    'technical': {
        'Accept': 'application/json',
        'X-Platform': 'Android',
        'Accept-Charset': 'UTF-8',
        'Content-Type': 'application/json',
        'Connection': 'keep-alive',
        'Accept-Encoding': 'gzip',
        'User-Agent': 'OneConnect/000000157 CFNetwork/1485 Darwin/23.1.0',
    }
}


class MySkodaSession(VWWebSession):
    def __init__(self, sessionuser, **kwargs):
        super(MySkodaSession, self).__init__(client_id='f9a2359a-b776-46d9-bd0c-db1904343117@apps_vw-dilab_com',
                                             refresh_url='https://api.connect.skoda-auto.cz/api/v1/authentication/token/refresh?systemId=technical',
                                             scope='openid mbb profile',
                                             redirect_uri='skodaconnect://oidc.login/',
                                             state=None,
                                             sessionuser=sessionuser,
                                             **kwargs)

        self.headers = CaseInsensitiveDict({
            'accept': '*/*',
            'content-type': 'application/json',
            'user-agent': 'OneConnect/000000157 CFNetwork/1485 Darwin/23.1.0',
            'accept-language': 'de-de',
            'accept-encoding': 'gzip, deflate, br'
        })

        self._session_tokens = {}

    def login(self, client='technical'):
        LOG.info('starting login with skoda session')
        self.cookies.clear()
        
        if client in self._session_tokens and  len(self._session_tokens[client]) > 0:
            LOG.info('Revoking old tokens for client %s.', client)
            try:
                self.logout(client)
            except:
                pass
        
        if client == 'connect':
            self.client_id = '7f045eee-7003-4379-9968-9355ed2adb06@apps_vw-dilab_com'
            self.scope= 'openid profile address cars email birthdate badge mbb phone driversLicense dealers profession vin mileage'
        if client == 'technical':
            self.client_id = 'f9a2359a-b776-46d9-bd0c-db1904343117@apps_vw-dilab_com'
            self.scope= 'openid mbb profile'
        authorizationUrl = self.authorizationUrl(url='https://identity.vwgroup.io/oidc/v1/authorize')
        LOG.info('starting webAuth')
        response = self.doWebAuth(authorizationUrl)
        LOG.info('starting fetchTokens with client %s', client)
        LOG.info('Client_id is: %s', self.client_id)
        LOG.info('Scope is: %s', self.scope)

        token_data = self.fetchTokens('https://api.connect.skoda-auto.cz/api/v1/authentication/token?systemId=' + client,
                         authorization_response=response
                         )
        
        self._session_tokens[client] = {}
        LOG.info('%s: token is fetched', client)

        # Assume that tokens were received OK
        if not 'error' in token_data:
            self._session_tokens[client]['access_token'] = token_data.get('access_token', token_data.get('accessToken', ''))
            self._session_tokens[client]['refresh_token'] = token_data.get('refresh_token', token_data.get('refreshToken', ''))
            self._session_tokens[client]['id_token'] = token_data.get('id_token', token_data.get('idToken', ''))
            self.token['client'] = client
        else:
            error = token_data.get('error', '')
            if 'error_description' in token_data:
                error_description = token_data.get('error_description', '')
                raise TemporaryAuthentificationError(f'{error} - {error_description}')
            else:
                raise TemporaryAuthentificationError(error)
        for key in self._session_tokens.get(client, {}):
            LOG.info(f'Got {key} for client {client}, token: "{self._session_tokens.get(client, {}).get(key, None)}"')
        if client != 'connect':
            self.login(client='connect')

    def logout(self, client:str):
        """Logout, revoke tokens."""
        try:
            refresh_token = self._session_tokens[client]['refresh_token']
            self.revoke_token(refresh_token, client)
        except:
            LOG.info('Some problem occured while revoking tokens, ignoring...')
            pass

    def revoke_token(self, refresh_token, client):
        """Revoke refresh token for supplied client."""
        try:
            req_headers = TOKEN_HEADERS[client]
            # "Skoda" tokens
            params: str = json.dumps(
                {
                    'refreshToken': refresh_token,
                })

            revoke_url = 'https://api.connect.skoda-auto.cz/api/v1/authentication/token/revoke?systemId='+client
            revokation_response = self.post(revoke_url, headers = req_headers, data = params)
            if revokation_response.status_code == requests.codes['no_content']:
                LOG.info(f'Revocation of token for client "{client}" successful')
                # Remove tokens from storage
                self._session_tokens[client] = {}
                return True
            else:
                LOG.info(f'Revocation of token for client "{client}" failed')
                return False
        except Exception as e:
            LOG.info(f'Revocation of token for {client} failed with error: {e}')
        return False

    def setToken(self, client:str):
        token = self._session_tokens[client]['access_token']
        valid = False
        if token is not False:
            valid = self.validate_token(token)
        if not valid:
            LOG.info(f'No valid access token for "{client}"')
            # Try to refresh tokens for client
            if self.refreshTokens(client) is not True:
                raise RetrievalError(f'No valid tokens for client "{client}"')
            else:
                LOG.info(f'Tokens refreshed successfully for client "{client}"')
                pass
        
        self.token = self._session_tokens[client]
        self.token['client'] = client

        self.accessToken = self._session_tokens[client]['access_token']
        self.refreshToken = self._session_tokens[client]['refresh_token']
        self.idToken = self._session_tokens[client]['id_token']


        if client == 'connect':
            self.client_id = '7f045eee-7003-4379-9968-9355ed2adb06@apps_vw-dilab_com'
            self.scope= 'openid profile address cars email birthdate badge mbb phone driversLicense dealers profession vin mileage'
        if client == 'technical':
            self.client_id = 'f9a2359a-b776-46d9-bd0c-db1904343117@apps_vw-dilab_com'
            self.scope= 'openid mbb profile'

    def validate_token(self, token):
        """Function to validate a single token."""
        try:
            now = datetime.now()
            exp = self.decode_token(token).get('exp', None)
            expires = datetime.fromtimestamp(int(exp))

            # Lazy check but it's very inprobable that the token expires the very second we want to use it
            if expires > now:
                return expires
            else:
                LOG.info(f'Token expired at {expires.strftime("%Y-%m-%d %H:%M:%S")})')
                return False
        except Exception as e:
            LOG.info(f'Token validation failed, {e}')
        return False
    
    def decode_token(self, token):
        """Helper method to deocde jwt token, different syntax in different versions."""
        # Try old pyJWT syntax first
        try:
            decoded = jwt.decode(token, verify=False)
        except:
            decoded = None
        # Try new pyJWT syntax if old fails
        if decoded is None:
            try:
                decoded = jwt.decode(token, options={'verify_signature': False})
            except:
                decoded = None
        if decoded is None:
            raise RetrievalError('Failed to decode token')
        else:
            return decoded


    def refresh(self):
        LOG.info("Refresh token for client: %s", self.token['client'])
        self.refreshTokens(
            self.token['client']
        )

    def doWebAuth(self, authorizationUrl):  # noqa: C901
        websession: requests.Session = requests.Session()
        retries = Retry(total=self.retries,
                        backoff_factor=0.1,
                        status_forcelist=[500],
                        raise_on_status=False)
        websession.proxies.update(self.proxies)
        websession.mount('https://', HTTPAdapter(max_retries=retries))
        websession.headers = CaseInsensitiveDict({
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'OneConnect/000000157 CFNetwork/1485 Darwin/23.1.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'x-requested-with': 'cz.skodaauto.connect',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
        })
        while True:
            loginFormResponse: requests.Response = websession.get(authorizationUrl, allow_redirects=False)
            if loginFormResponse.status_code == requests.codes['ok']:
                break
            elif loginFormResponse.status_code == requests.codes['found']:
                if 'Location' in loginFormResponse.headers:
                    authorizationUrl = loginFormResponse.headers['Location']
                else:
                    raise APICompatibilityError('Forwarding without Location in Header')
            elif loginFormResponse.status_code == requests.codes['internal_server_error']:
                raise RetrievalError('Temporary server error during login')
            else:
                raise APICompatibilityError('Retrieving credentials page was not successfull,'
                                            f' status code: {loginFormResponse.status_code}')

        # Find login form on page to obtain inputs
        emailFormRegex = r'<form.+id=\"emailPasswordForm\".*action=\"(?P<formAction>[^\"]+)\"[^>]*>' \
            r'(?P<formContent>.+?(?=</form>))</form>'
        match: Optional[Match[str]] = re.search(emailFormRegex, loginFormResponse.text, flags=re.DOTALL)
        if match is None:
            raise APICompatibilityError('No login email form found')
        # retrieve target url from form
        target: str = match.groupdict()['formAction']

        # Find all inputs and put those in formData dictionary
        inputRegex = r'<input[\\n\\r\s][^/]*name=\"(?P<name>[^\"]+)\"([\\n\\r\s]value=\"(?P<value>[^\"]+)\")?[^/]*/>'
        formData: Dict[str, str] = {}
        for match in re.finditer(inputRegex, match.groupdict()['formContent']):
            if match.groupdict()['name']:
                formData[match.groupdict()['name']] = match.groupdict()['value']
        if not all(x in ['_csrf', 'relayState', 'hmac', 'email'] for x in formData):
            raise APICompatibilityError('Could not find all required input fields in login page')

        # Set email to the provided username
        formData['email'] = self.sessionuser.username
        LOG.info('username in skoda_session is: %s', formData['email'])

        # build url from form action
        login2Url: str = 'https://identity.vwgroup.io' + target

        loginHeadersForm: CaseInsensitiveDict = websession.headers.copy()
        loginHeadersForm['Content-Type'] = 'application/x-www-form-urlencoded'

        # Post form content and retrieve credentials page
        LOG.info('staring with authentication 2URL')
        login2Response: requests.Response = websession.post(login2Url, headers=loginHeadersForm, data=formData, allow_redirects=True)

        if login2Response.status_code != requests.codes['ok']:  # pylint: disable=E1101
            if login2Response.status_code == requests.codes['internal_server_error']:
                raise RetrievalError('Temporary server error during login')
            raise APICompatibilityError('Retrieving credentials page was not successfull,'
                                        f' status code: {login2Response.status_code}')

        credentialsTemplateRegex = r'<script>\s+window\._IDK\s+=\s+\{\s' \
            r'(?P<templateModel>.+?(?=\s+\};?\s+</script>))\s+\};?\s+</script>'
        match = re.search(credentialsTemplateRegex, login2Response.text, flags=re.DOTALL)
        if match is None:
            raise APICompatibilityError('No credentials form found')
        if match.groupdict()['templateModel']:
            lineRegex = r'\s*(?P<name>[^\:]+)\:\s+[\'\{]?(?P<value>.+)[\'\}][,]?'
            form2Data: Dict[str, str] = {}
            for match in re.finditer(lineRegex, match.groupdict()['templateModel']):
                if match.groupdict()['name'] == 'templateModel':
                    templateModelString = '{' + match.groupdict()['value'] + '}'
                    if templateModelString.endswith(','):
                        templateModelString = templateModelString[:-len(',')]
                    templateModel = json.loads(templateModelString)
                    if 'relayState' in templateModel:
                        form2Data['relayState'] = templateModel['relayState']
                    if 'hmac' in templateModel:
                        form2Data['hmac'] = templateModel['hmac']
                    if 'emailPasswordForm' in templateModel and 'email' in templateModel['emailPasswordForm']:
                        form2Data['email'] = templateModel['emailPasswordForm']['email']
                    if 'error' in templateModel and templateModel['error'] is not None:
                        if templateModel['error'] == 'validator.email.invalid':
                            raise AuthentificationError('Error during login, email invalid')
                        raise AuthentificationError(f'Error during login: {templateModel["error"]}')
                    if 'registerCredentialsPath' in templateModel and templateModel['registerCredentialsPath'] == 'register':
                        raise AuthentificationError(f'Error during login, account {self.sessionuser.username} does not exist')
                    if 'errorCode' in templateModel:
                        raise AuthentificationError('Error during login, is the username correct?')
                    if 'postAction' in templateModel:
                        target = templateModel['postAction']
                    else:
                        raise APICompatibilityError('Form does not contain postAction')
                elif match.groupdict()['name'] == 'csrf_token':
                    form2Data['_csrf'] = match.groupdict()['value']
        form2Data['password'] = self.sessionuser.password
        if not all(x in ['_csrf', 'relayState', 'hmac', 'email', 'password'] for x in form2Data):
            raise APICompatibilityError('Could not find all required input fields in login page')
        LOG.info('staring with authentication 3URL')
        login3Url = f'https://identity.vwgroup.io/signin-service/v1/{self.client_id}/{target}'

        # Post form content and retrieve userId in forwarding Location
        login3Response: requests.Response = websession.post(login3Url, headers=loginHeadersForm, data=form2Data, allow_redirects=False)
        if login3Response.status_code not in (requests.codes['found'], requests.codes['see_other']):
            if login3Response.status_code == requests.codes['internal_server_error']:
                LOG.info("Retrieval error with status code %s", login3Response.status_code)
                raise RetrievalError('Temporary server error during login')
            raise APICompatibilityError('Forwarding expected (status code 302),'
                                        f' but got status code {login3Response.status_code}')
        if 'Location' not in login3Response.headers:
            raise APICompatibilityError('No url for forwarding in response headers')

        # Parse parametes from forwarding url
        params: Dict[str, str] = dict(parse_qsl(urlsplit(login3Response.headers['Location']).query))

        # Check if error
        if 'error' in params and params['error']:
            errorMessages: Dict[str, str] = {
                'login.errors.password_invalid': 'Password is invalid',
                'login.error.throttled': 'Login throttled, probably too many wrong logins. You have to wait some'
                                         ' minutes until a new login attempt is possible'
            }
            if params['error'] in errorMessages:
                error = errorMessages[params['error']]
            else:
                error = params['error']
            LOG.info("problem with authentication: %s", error)
            raise AuthentificationError(error)

        # Check for user id
        if 'userId' not in params or not params['userId']:
            if 'updated' in params and params['updated'] == 'dataprivacy':
                LOG.info("You have to login at myvolkswagen.de and accept the terms and conditions")
                raise AuthentificationError('You have to login at myvolkswagen.de and accept the terms and conditions')
            LOG.info("No user id provided")
            raise APICompatibilityError('No user id provided')
        self.userId = params['userId']  # pylint: disable=unused-private-member

        # Now follow the forwarding until forwarding URL starts with 'weconnect://authenticated#'
        afterLoginUrl: str = login3Response.headers['Location']

        consentURL = None
        while True:
            if 'consent' in afterLoginUrl:
                consentURL = afterLoginUrl
            afterLoginResponse = self.get(afterLoginUrl, allow_redirects=False, access_type=AccessType.NONE)
            if afterLoginResponse.status_code == requests.codes['internal_server_error']:
                raise RetrievalError('Temporary server error during login')

            if 'Location' not in afterLoginResponse.headers:
                if consentURL is not None:
                    LOG.info("It seems like you need to accept the terms and conditions for the MySkoda service. Visit %s", consentURL)
                    raise AuthentificationError('It seems like you need to accept the terms and conditions for the MySkoda service.'
                                                f' Try to visit the URL "{consentURL}" or log into the MySkoda smartphone app')
                LOG.info("No Location for forwarding in response headers. PROBLEM..")
                raise APICompatibilityError('No Location for forwarding in response headers')

            afterLoginUrl = afterLoginResponse.headers['Location']

            if afterLoginUrl.startswith(self.redirect_uri):
                break

        if afterLoginUrl.startswith(self.redirect_uri + '#'):
            queryurl = afterLoginUrl.replace(self.redirect_uri + '#', 'https://egal?')
        else:
            queryurl = afterLoginUrl
        return queryurl

    def fetchTokens(
        self,
        token_url,
        authorization_response=None,
        **kwargs
    ):

        self.parseFromFragment(authorization_response)

        if all(key in self.token for key in ('state', 'id_token', 'access_token', 'code')):
            body: str = json.dumps(
                {
                    #'state': self.token['state'],
                    #'id_token': self.token['id_token'],
                    #'redirect_uri': self.redirect_uri,
                    #'region': 'emea',
                    #'access_token': self.token['access_token'],
                    'authorizationCode': self.token['code'],
                })

            loginHeadersForm: CaseInsensitiveDict = self.headers
            loginHeadersForm['content-type'] = 'application/json; charset=utf-8'


            tokenResponse = self.post(token_url, headers=loginHeadersForm, data=body, allow_redirects=False)
            if tokenResponse.status_code != requests.codes['ok']:
                print(tokenResponse.text)
                LOG.info("Token response status from fetch is %s", tokenResponse.status_code)
                raise TemporaryAuthentificationError(f'Token could not be fetched due to temporary MySkoda failure: {tokenResponse.status_code}')
            
            token = self.parseFromBody(tokenResponse.text)

            return token

    def parseFromBody(self, token_response, state=None):
        try:
            token = json.loads(token_response)
        except json.decoder.JSONDecodeError:
            raise TemporaryAuthentificationError('Token could not be refreshed due to temporary MySkoda failure: json could not be decoded')
        if 'accessToken' in token:
            token['access_token'] = token.pop('accessToken')
        if 'idToken' in token:
            token['id_token'] = token.pop('idToken')
        if 'refreshToken' in token:
            token['refresh_token'] = token.pop('refreshToken')
        fixedTokenresponse = to_unicode(json.dumps(token)).encode("utf-8")
        return super(MySkodaSession, self).parseFromBody(token_response=fixedTokenresponse, state=state)
    
    def refreshTokens(
        self,
        client,
        refresh_token=None,
        auth=None,
        timeout=None,
        headers=None,
        verify=True,
        proxies=None,
        **kwargs
    ):
        token_url = 'https://api.connect.skoda-auto.cz/api/v1/authentication/token/refresh?systemId=' + client
        LOG.info('Refreshing tokens with url: %s', token_url)
        if not token_url:
            raise ValueError("No token endpoint set for auto_refresh.")

        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        client = self.token['client']
        if headers is None:
            headers = TOKEN_HEADERS.get(client)
        
        body: str = json.dumps(
                {
                    'refreshToken': self.token['refresh_token'],
                })

        LOG.info('Firing post request for refresh!')
        tokenResponse = self.post(
            token_url,
            data=body,
            auth=auth,
            timeout=timeout,
            headers=headers
        )
        LOG.info("TokenResponse from refresh is %s", tokenResponse.status_code)
        if tokenResponse.status_code == requests.codes['unauthorized']:
            raise AuthentificationError('Refreshing tokens failed: Server requests new authorization')
        elif tokenResponse.status_code in (requests.codes['internal_server_error'], requests.codes['service_unavailable'], requests.codes['gateway_timeout']):
            raise TemporaryAuthentificationError('Token could not be refreshed due to temporary MySkoda failure: {tokenResponse.status_code}')
        elif tokenResponse.status_code == requests.codes['ok']:
            LOG.info("Refresh is successful!")
            self.revoke_token(self.token['refresh_token'], client)
            LOG.info("Revoke old token successful!")
            token_data = self.parseFromBody(tokenResponse.text)

            self._session_tokens[client]['access_token'] = token_data.get('access_token', token_data.get('accessToken', ''))
            self._session_tokens[client]['refresh_token'] = token_data.get('refresh_token', token_data.get('refreshToken', ''))
            self._session_tokens[client]['id_token'] = token_data.get('id_token', token_data.get('idToken', ''))
            self.token['client'] = client
            if "refresh_token" not in self.token:
                LOG.info("No new refresh token given. Re-using old.")
                self.token["refresh_token"] = refresh_token
            return self.token
        else:
            raise RetrievalError(f'Status Code from MySkoda while refreshing tokens was: {tokenResponse.status_code}')

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        withhold_token=False,
        access_type=AccessType.ACCESS,
        token=None,
        timeout=None,
        **kwargs
    ):
        """Intercept all requests and add userId if present."""
        if not is_secure_transport(url):
            raise InsecureTransportError()
        if self.userId is not None:
            headers = headers or {}
            #headers['user-id'] = self.userId

        return super(MySkodaSession, self).request(method, url, headers=headers, data=data, withhold_token=withhold_token, access_type=access_type, token=token,
                                                   timeout=timeout, **kwargs)
