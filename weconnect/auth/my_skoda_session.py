"""
Module implements the Skoda Session handling.
"""
import json
import logging
import base64
import hashlib
import random
import string

from urllib.parse import parse_qsl, urlparse

import requests
from requests.models import CaseInsensitiveDict
from requests.exceptions import ReadTimeout, ConnectionError

from oauthlib.common import add_params_to_uri, generate_nonce, to_unicode
from oauthlib.oauth2 import InsecureTransportError
from oauthlib.oauth2 import is_secure_transport

from weconnect.auth.openid_session import AccessType
from weconnect.auth.skoda_web_session import SkodaWebSession
from weconnect.errors import AuthentificationError, RetrievalError, TemporaryAuthentificationError


LOG = logging.getLogger("weconnect")


class MySkodaSession(SkodaWebSession):
    """
    MySkodaSession class handles the authentication and session management for Skoda's MySkoda service.
    """
    def __init__(self, sessionuser=None, token=None, metadata=None, **kwargs):
        # Extract sessionuser before passing to parent
        self.sessionuser = sessionuser
        super(MySkodaSession, self).__init__(session_user=sessionuser, cache=None, accept_terms_on_login=False,
                                             client_id='7f045eee-7003-4379-9968-9355ed2adb06@apps_vw-dilab_com',
                                             refresh_url='https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/refresh-token?tokenType=CONNECT',
                                             scope='address badge birthdate cars driversLicense dealers email mileage mbb nationalIdentifier openid phone profession profile vin',
                                             redirect_uri='myskoda://redirect/login/',
                                             state=None,
                                             token=token,
                                             metadata=metadata,
                                             **kwargs)

        self.headers = CaseInsensitiveDict({
            'user-agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 '
                          'Chrome/74.0.3729.185 Mobile Safari/537.36',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
                      'application/signed-exchange;v=b3',
            'accept-language': 'en-US,en;q=0.9',
            'accept-encoding': 'gzip, deflate',
            'x-requested-with': 'cz.skodaauto.connect',
            'upgrade-insecure-requests': '1',
        })

    def login(self):
        super(MySkodaSession, self).login()
        # Clear connection pools before login to prevent stale connection reuse
        # This is critical to prevent "Remote end closed connection without response" errors
        if hasattr(self, '_clear_connection_pools'):
            self._clear_connection_pools()

        try:
            verifier = "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
            verifier_hash = hashlib.sha256(verifier.encode("utf-8")).digest()
            code_challenge = base64.b64encode(verifier_hash).decode("utf-8").replace("+", "-").replace("/", "_").rstrip("=")
            authorizationUrl = self.authorizationUrl(url='https://identity.vwgroup.io/oidc/v1/authorize', prompt='login',
                                                    code_challenge=code_challenge, code_challenge_method='s256')
            response = self.do_web_auth(authorizationUrl)
            self.fetchTokens('https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/exchange-authorization-code?tokenType=CONNECT',
                             authorization_response=response, verifier=verifier)
        except ReadTimeout as exc:
            raise TemporaryAuthentificationError('Login timed out (Read timeout)') from exc
        except ConnectionError as exc:
            raise TemporaryAuthentificationError('Login failed due to connection error') from exc

    def refresh(self):
        self.refreshTokens(
            'https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/refresh-token?tokenType=CONNECT',
        )

    def authorizationUrl(self, url, state=None, code_challenge=None, code_challenge_method=None, prompt=None, **kwargs):
        if state is not None:
            raise AuthentificationError('Do not provide state')

        params = [('redirect_uri', self.redirect_uri),
                  ('nonce', generate_nonce())]

        if code_challenge is not None:
            params.append(('code_challenge', code_challenge))
        if code_challenge_method is not None:
            params.append(('code_challenge_method', code_challenge_method))
        if prompt is not None:
            params.append(('prompt', prompt))

        # Add client_id, scope, and response_type to the authorization URL
        params.append(('client_id', self.client_id))
        params.append(('scope', self.scope))
        params.append(('response_type', 'code'))
        
        authUrl = add_params_to_uri('https://identity.vwgroup.io/oidc/v1/authorize', params)

        tryLoginResponse = self.get(authUrl, allow_redirects=False, access_type=AccessType.NONE)
        
        # Debug: Print response status and headers
        LOG.debug(f"Authorization URL response status: {tryLoginResponse.status_code}")
        LOG.debug(f"Authorization URL response headers: {dict(tryLoginResponse.headers)}")
        
        if tryLoginResponse.status_code != 302 and 'location' not in tryLoginResponse.headers:
            LOG.error(f"Authorization failed. Response body: {tryLoginResponse.text[:500]}")
            raise AuthentificationError(f"Authorization failed with status {tryLoginResponse.status_code}")
        
        redirect = tryLoginResponse.headers.get('Location', tryLoginResponse.headers.get('location'))
        query = urlparse(redirect).query
        params = dict(parse_qsl(query))
        if 'state' in params:
            self.state = params.get('state')

        return redirect

    def fetchTokens(
        self,
        token_url,
        authorization_response=None,
        verifier=None,
        **kwargs
    ):
        # For Skoda, we don't use parseFromFragment as it checks state
        # Instead, we parse the URL directly to get the authorization code
        from urllib.parse import urlparse, parse_qsl
        
        # Parse the authorization response to extract code
        parsed = urlparse(authorization_response)
        params = dict(parse_qsl(parsed.query))
        
        if 'code' in params:
            self.token = {'code': params['code']}
        elif 'error' in params:
            raise AuthentificationError(f"Authorization error: {params.get('error_description', params.get('error'))}")
        else:
            raise AuthentificationError("No authorization code received")

        if self.token is not None and 'code' in self.token:
            body: str = json.dumps(
                {
                    'redirectUri': 'myskoda://redirect/login/',
                    'code': self.token['code'],
                    'verifier': verifier
                })

            request_headers: CaseInsensitiveDict = self.headers
            request_headers['accept'] = 'application/json'
            request_headers['content-type'] = 'application/json'

            tokenResponse = self.post(token_url, headers=request_headers, data=body, allow_redirects=False,
                                      access_type=AccessType.NONE)
            if tokenResponse.status_code != requests.codes['ok']:
                raise TemporaryAuthentificationError(f'Token could not be fetched due to temporary MySkoda failure: {tokenResponse.status_code}')
            token = self.parseFromBody(tokenResponse.text)
            return token
        return None

    def parseFromBody(self, token_response, state=None):
        """
            Fix strange token naming before parsing it with OAuthlib.
        """
        try:
            # Tokens are in body of response in json format
            token = json.loads(token_response)
        except json.decoder.JSONDecodeError as err:
            raise TemporaryAuthentificationError('Token could not be refreshed due to temporary MySkoda failure: json could not be decoded') from err
        found_tokens = set()
        # Fix token keys, we want access_token instead of accessToken
        if 'accessToken' in token:
            found_tokens.add('accessToken')
            token['access_token'] = token.pop('accessToken')
        # Fix token keys, we want id_token instead of idToken
        if 'idToken' in token:
            found_tokens.add('idToken')
            token['id_token'] = token.pop('idToken')
        # Fix token keys, we want refresh_token instead of refreshToken
        if 'refreshToken' in token:
            found_tokens.add('refreshToken')
            token['refresh_token'] = token.pop('refreshToken')
        LOG.debug(f'Found tokens in answer: {found_tokens}')
        # generate json from fixed dict
        fixedTokenresponse = to_unicode(json.dumps(token)).encode("utf-8")
        # Let OAuthlib parse the token (this internally sets self.token)
        return super(MySkodaSession, self).parseFromBody(token_response=fixedTokenresponse, state=state)

    def refreshTokens(
        self,
        token_url,
        refresh_token=None,
        auth=None,
        timeout=None,
        headers=None,
        verify=True,
        proxies=None,
        **kwargs
    ):
        LOG.info('Refreshing Skoda tokens')
        if not token_url:
            raise ValueError("No token endpoint set for auto_refresh.")

        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        refresh_token = refresh_token or self.refreshToken

        if refresh_token is None:
            refresh_token = self.refreshToken
            if refresh_token is None and self.token is not None:
                refresh_token = self.token.get('refresh_token')

        if not refresh_token:
            raise AuthentificationError('No refresh token available. Please log in again.')

        # Close any idle connections to prevent reusing stale connections
        # This helps prevent "Remote end closed connection without response" errors
        # that occur when trying to reuse a connection that the server has closed
        try:
            # Get the HTTPAdapter and close idle connections in the pool
            adapter = self.get_adapter(token_url)
            if hasattr(adapter, 'poolmanager') and adapter.poolmanager is not None:
                # Clear idle connections from the pool
                adapter.poolmanager.clear()
                LOG.debug("Cleared connection pool before token refresh")
        except Exception as e:
            # If clearing fails, log but continue - not critical
            LOG.debug("Could not clear connection pool: %s", str(e))

        # Use a shorter timeout for token refresh to prevent stale connection issues
        # Token endpoints should respond quickly; 30 seconds is more than enough
        # This prevents holding connections open for 180 seconds which can lead to
        # "Remote end closed connection without response" errors
        if timeout is None:
            timeout = 30

        tHeaders = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
            "x-requested-with": "cz.skodaauto.connect",
        }

        body = json.dumps({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        })

        try:
            tokenResponse = self.post(
                token_url,
                data=body,
                headers=tHeaders,
                timeout=timeout,
                verify=verify,
                proxies=proxies,
                access_type=AccessType.NONE,
            )
            if tokenResponse.status_code == requests.codes['ok']:
                # parse token from response body (this internally sets self.token)
                newToken = self.parseFromBody(tokenResponse.text)
                if newToken is not None and "refresh_token" not in newToken:
                    LOG.debug("No new refresh token given. Re-using old.")
                    self.token["refresh_token"] = refresh_token
                    self.token = newToken
                return newToken
            elif tokenResponse.status_code == requests.codes['unauthorized']:
                LOG.error('Token refresh failed with 401 - server requests new authorization. Refresh token may be expired or invalid.')
                raise AuthentificationError('Refreshing tokens failed: Server requests new authorization. Please log in again.')
            elif tokenResponse.status_code in (requests.codes['internal_server_error'], requests.codes['service_unavailable'], requests.codes['gateway_timeout']):
                raise TemporaryAuthentificationError(f'Token could not be refreshed due to temporary MySkoda failure: {tokenResponse.status_code}')
            else:
                raise RetrievalError(f'Status Code from MySkoda while refreshing tokens was: {tokenResponse.status_code}')
        except ConnectionError:
            # Retry once on connection error
            LOG.warning('Connection error during token refresh, retrying once')
            try:
                self._clear_connection_pools()
                tokenResponse = self.post(
                    token_url,
                    data=body,
                    headers=tHeaders,
                    timeout=timeout,
                    verify=verify,
                    proxies=proxies,
                    access_type=AccessType.NONE,
                )
                if tokenResponse.status_code == requests.codes['ok']:
                    newToken = self.parseFromBody(tokenResponse.text)
                    if newToken is not None and "refresh_token" not in newToken:
                        LOG.debug("No new refresh token given. Re-using old.")
                        self.token["refresh_token"] = refresh_token
                        self.token = newToken
                    return newToken
                elif tokenResponse.status_code == requests.codes['unauthorized']:
                    raise AuthentificationError('Refreshing tokens failed: Server requests new authorization. Please log in again.')
                else:
                    raise RetrievalError(f'Status Code from MySkoda while refreshing tokens was: {tokenResponse.status_code}')
            except Exception as e:
                LOG.error('Retry also failed: %s', str(e))
                raise AuthentificationError('Token refresh failed. Please log in again.') from e
