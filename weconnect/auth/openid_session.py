import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from enum import Enum, auto
import time
from datetime import datetime, timezone
import logging
import jwt
import requests

from oauthlib.common import generate_nonce, generate_token, UNICODE_ASCII_CHARACTER_SET
from oauthlib.oauth2.rfc6749.parameters import parse_authorization_code_response, parse_token_response, prepare_grant_uri
from oauthlib.oauth2.rfc6749.errors import InsecureTransportError, TokenExpiredError, MissingTokenError
from oauthlib.oauth2.rfc6749.utils import is_secure_transport

from requests.adapters import HTTPAdapter

from requests.adapters import HTTPAdapter

from weconnect.auth.auth_util import addBearerAuthHeader
from weconnect.errors import AuthentificationError, RetrievalError

from weconnect.elements.helpers.blacklist_retry import BlacklistRetry


LOG = logging.getLogger("weconnect")


class AccessType(Enum):
    NONE = auto()
    ACCESS = auto()
    ID = auto()
    REFRESH = auto()


class OpenIDSession(requests.Session):
    def __init__(self, client_id=None, redirect_uri=None, refresh_url=None, scope=None, token=None, metadata={}, state=None, timeout=None,
                 forceReloginAfter=None, **kwargs):
        super(OpenIDSession, self).__init__(**kwargs)
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.refresh_url = refresh_url
        self.scope = scope
        self.state = state or generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET)

        self.timeout = timeout
        self._token = None
        self.token = token
        self.metadata = metadata
        self.lastLogin = None
        self.forceReloginAfter = forceReloginAfter

        self._retries = False

    @property
    def forceReloginAfter(self):
        return self._forceReloginAfter

    @forceReloginAfter.setter
    def forceReloginAfter(self, newValue):
        self._forceReloginAfter = newValue
        if newValue is not None and self.lastLogin is None:
            self.lastLogin = time.time()

    @property
    def retries(self):
        return self._retries

    @retries.setter
    def retries(self, newValue):
        self._retries = newValue
        if newValue:
            # Retry on internal server error (500)
            retries = BlacklistRetry(total=newValue,
                                     backoff_factor=0.1,
                                     status_forcelist=[500],
                                     status_blacklist=[429],
                                     raise_on_status=False)
            # Configure connection pool to prevent stale connection reuse
            # pool_connections: number of connection pools to cache
            # pool_maxsize: maximum number of connections to save in the pool
            # This helps prevent "Remote end closed connection without response" errors
            self.mount('https://', HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20))

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, newToken):
        if newToken is not None:
            # ALWAYS decode the access_token JWT to see what it actually says
            jwt_expires_in = None
            jwt_expires_at = None
            server_expires_in = newToken.get('expires_in')

            if 'access_token' in newToken:
                try:
                    meta_data = jwt.decode(newToken['access_token'], options={"verify_signature": False})
                    if 'exp' in meta_data:
                        jwt_expires_at = meta_data['exp']
                        expires_at_dt = datetime.fromtimestamp(meta_data['exp'], tz=timezone.utc)
                        jwt_expires_in = (expires_at_dt - datetime.now(tz=timezone.utc)).total_seconds()
                        LOG.debug(f"JWT says access_token expires in: {jwt_expires_in:.0f} seconds")
                except Exception:  # pylint: disable=broad-except
                    LOG.warning("Could not decode access_token JWT")

            # Log comparison if server provided expires_in
            if server_expires_in is not None and jwt_expires_in is not None:
                server_val = float(server_expires_in)
                LOG.debug(f"Server says: {server_val:.0f}s, JWT says: {jwt_expires_in:.0f}s, Difference: {abs(server_val - jwt_expires_in):.0f}s")

            # Now decide which value to use
            if 'expires_in' not in newToken:
                # Server didn't provide expires_in, use JWT or fallback
                if jwt_expires_in is not None:
                    newToken['expires_in'] = jwt_expires_in
                    newToken['expires_at'] = jwt_expires_at
                    LOG.debug("Using JWT expiry (server didn't provide expires_in)")
                elif 'id_token' in newToken:
                    try:
                        meta_data = jwt.decode(newToken['id_token'], options={"verify_signature": False})
                        if 'exp' in meta_data:
                            newToken['expires_at'] = meta_data['exp']
                            expires_at = datetime.fromtimestamp(meta_data['exp'], tz=timezone.utc)
                            newToken['expires_in'] = (expires_at - datetime.now(tz=timezone.utc)).total_seconds()
                    except Exception:  # pylint: disable=broad-except
                        LOG.debug("Could not decode id_token JWT")
                if 'expires_in' not in newToken:
                    if self._token is not None and 'expires_in' in self._token:
                        newToken['expires_in'] = self._token['expires_in']
                    else:
                        newToken['expires_in'] = 3600
            # If expires_in is set and expires_at is not set we calculate expires_at from expires_in using the current time
            if 'expires_in' in newToken and 'expires_at' not in newToken:
                newToken['expires_at'] = time.time() + int(newToken.get('expires_in'))
            if newToken['expires_in'] > 3600:
                LOG.warning('unexpected Token expires_in > 3600s (%d)', newToken['expires_in'])
            if newToken['expires_at'] > (time.time() + 3600):
                LOG.warning('unexpected Token expires_at after more than 3600s')

            # Ensure expires_in and expires_at are always numeric (Skoda may send them as strings)
            if 'expires_in' in newToken:
                try:
                    newToken['expires_in'] = float(newToken['expires_in'])
                except (ValueError, TypeError):
                    LOG.warning(f"Could not convert expires_in to float: {newToken['expires_in']}")
            if 'expires_at' in newToken:
                try:
                    newToken['expires_at'] = float(newToken['expires_at'])
                except (ValueError, TypeError):
                    LOG.warning(f"Could not convert expires_at to float: {newToken['expires_at']}")

        self._token = newToken

    @property
    def accessToken(self):
        if self._token is not None and 'access_token' in self._token:
            return self._token.get('access_token')
        return None

    @accessToken.setter
    def accessToken(self, newValue):
        if self._token is None:
            self._token = {}
        self._token['access_token'] = newValue

    @property
    def refreshToken(self):
        if self._token is not None and 'refresh_token' in self._token:
            return self._token.get('refresh_token')
        return None

    @property
    def idToken(self):
        if self._token is not None and 'id_token' in self._token:
            return self._token.get('id_token')
        return None

    @property
    def tokenType(self):
        if self._token is not None and 'token_type' in self._token:
            return self._token.get('token_type')
        return None

    @property
    def expiresIn(self):
        if self._token is not None and 'expires_in' in self._token:
            return self._token.get('expires_in')
        return None

    @property
    def expiresAt(self):
        if self._token is not None and 'expires_at' in self._token:
            return self._token.get('expires_at')
        return None

    @property
    def authorized(self):
        return bool(self.accessToken)

    @property
    def expired(self):
        return self.expiresAt is not None and self.expiresAt < time.time()

    @property
    def userId(self):
        if 'userId' in self.metadata:
            return self.metadata['userId']
        return None

    @userId.setter
    def userId(self, newUserId):
        self.metadata['userId'] = newUserId

    def _clear_connection_pools(self):
        """Clear connection pools to prevent stale connection reuse."""
        for adapter in self.adapters.values():
            if hasattr(adapter, 'poolmanager') and adapter.poolmanager is not None:
                adapter.poolmanager.clear()
        LOG.debug("Cleared connection pools")

    def login_with_retry(self):
        """
        Wrapper around login() that retries once on connection errors.
        This handles stale connections that cause "Remote end closed connection without response" errors.
        """
        try:
            self.login()
        except requests.exceptions.ConnectionError as conn_error:
            LOG.warning('Connection error during login, retrying once with fresh connection pool: %s', str(conn_error))
            # Clear connection pools and retry
            try:
                self._clear_connection_pools()
            except Exception as e:
                LOG.debug('Could not clear connection pools: %s', str(e))
            # Retry the login once
            self.login()

    def login(self):
        self.lastLogin = time.time()

    def refresh(self):
        pass

    def authorizationUrl(self, url, state=None, **kwargs):
        state = state or self.state
        authUrl = prepare_grant_uri(uri=url, client_id=self.client_id, redirect_uri=self.redirect_uri, response_type='code id_token token', scope=self.scope,
                                    state=state, nonce=generate_nonce(), **kwargs)
        return authUrl

    def parseFromFragment(self, authorization_response, state=None):
        state = state or self.state
        self.token = parse_authorization_code_response(authorization_response, state=state)
        return self.token

    def parseFromBody(self, token_response, state=None):
        self.token = parse_token_response(token_response, scope=self.scope)
        return self.token

    def request(  # noqa: C901
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
        """Intercept all requests and add the OAuth 2 token if present."""
        # Skip security check for localhost/development or if explicitly disabled
        url_lower = url.lower() if url else ''
        if not (url_lower.startswith('https://') or url_lower.startswith('http://localhost') or url_lower.startswith('http://127.0.0.1')):
            if not is_secure_transport(url):
                raise InsecureTransportError()
        if access_type != AccessType.NONE and not withhold_token:
            if self.forceReloginAfter is not None and self.lastLogin is not None and (self.lastLogin + self.forceReloginAfter) < time.time():
                LOG.debug("Forced new login after %ds", self.forceReloginAfter)
                self.login_with_retry()
            try:
                url, headers, data = self.addToken(url, body=data, headers=headers, access_type=access_type, token=token)
            # Attempt to retrieve and save new access token if expired
            except TokenExpiredError:
                LOG.info('Token expired')
                self.accessToken = None
                try:
                    self.refresh()
                except AuthentificationError as authError:
                    # Check if this is a "Server requests new authorization" error
                    if 'Server requests new authorization' in str(authError):
                        LOG.warning('Server requests new authorization - clearing tokens and forcing re-login')
                        # Clear all tokens to force fresh login
                        if hasattr(self, 'clear_tokens'):
                            self.clearTokens()
                        else:
                            # Fallback for base class
                            self.token = None
                            self.accessToken = None
                            self.refreshToken = None
                            self.idToken = None
                        LOG.info('Authentication failed during refresh - attempting new login')
                        self.login_with_retry()
                except TokenExpiredError:
                    self.login_with_retry()
                except MissingTokenError:
                    self.login_with_retry()
                except RetrievalError:
                    LOG.error('Retrieval Error while refreshing token. Probably the token was invalidated. Trying to do a new login instead.')
                    self.login_with_retry()
                url, headers, data = self.addToken(url, body=data, headers=headers, access_type=access_type, token=token)
            except MissingTokenError:
                LOG.error('Missing token')
                self.login_with_retry()
                url, headers, data = self.addToken(url, body=data, headers=headers, access_type=access_type, token=token)

        if timeout is None:
            timeout = self.timeout

        return super(OpenIDSession, self).request(
            method, url, headers=headers, data=data, **kwargs
        )

    def addToken(self, uri, body=None, headers=None, access_type=AccessType.ACCESS, token=None, **kwargs):
        if not is_secure_transport(uri):
            raise InsecureTransportError()

        if token is None:
            if access_type == AccessType.ID:
                if not (self.idToken):
                    raise MissingTokenError(description="Missing id token.")
                token = self.idToken
            elif access_type == AccessType.REFRESH:
                if not (self.refreshToken):
                    raise MissingTokenError(description="Missing refresh token.")
                token = self.refreshToken
            else:
                if not self.authorized:
                    self.login_with_retry()
                if not (self.accessToken):
                    raise MissingTokenError(description="Missing access token.")
                if self.expired:
                    raise TokenExpiredError()
                token = self.accessToken

        headers = addBearerAuthHeader(token, headers)

        return (uri, headers, body)
