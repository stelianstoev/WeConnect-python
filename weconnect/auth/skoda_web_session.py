"""
Module implements Skoda web session handling.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from urllib.parse import parse_qsl, urlparse, urlsplit, urljoin

from urllib3.util.retry import Retry

import requests
from requests.adapters import HTTPAdapter
from requests.models import CaseInsensitiveDict

from weconnect.errors import APICompatibilityError, AuthentificationError, RetrievalError

from weconnect.auth.auth_util import CredentialsFormParser, HTMLFormParser, TermsAndConditionsFormParser
from weconnect.auth.openid_session import OpenIDSession

if TYPE_CHECKING:
    from typing import Any, Dict


class SkodaWebSession(OpenIDSession):
    """
    SkodaWebSession handles the web authentication process for Skoda's web services.
    """
    def __init__(self, session_user=None, cache=None, accept_terms_on_login=False, **kwargs):
        super(SkodaWebSession, self).__init__(**kwargs)
        self.session_user = session_user
        self.cache = cache
        self.accept_terms_on_login: bool = accept_terms_on_login

        retries = Retry(
            total=self.retries,
            backoff_factor=0.1,
            status_forcelist=[500],
            raise_on_status=False
        )

        self.websession: requests.Session = requests.Session()
        self.websession.proxies.update(self.proxies)
        self.websession.mount('https://', HTTPAdapter(max_retries=retries))
        self.websession.headers = CaseInsensitiveDict({
            'user-agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 '
                          'Chrome/74.0.3729.185 Mobile Safari/537.36',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
                      'application/signed-exchange;v=b3',
            'accept-language': 'en-US,en;q=0.9',
            'accept-encoding': 'gzip, deflate',
            'x-requested-with': 'cz.skodaauto.connect',
            'upgrade-insecure-requests': '1',
        })

    def do_web_auth(self, url: str) -> str:
        email_form: HTMLFormParser = self._get_login_form(url)

        email_form.data['email'] = self.session_user.username

        password_form = self._get_password_form(
            urljoin('https://identity.vwgroup.io', email_form.target),
            email_form.data
        )

        password_form.data['email'] = self.session_user.username
        password_form.data['password'] = self.session_user.password

        url = self._handle_login(
            f'https://identity.vwgroup.io/signin-service/v1/{self.client_id}/{password_form.target}',
            password_form.data
        )

        if self.redirect_uri is None:
            raise ValueError('Redirect URI is not set')
        while True:
            if url.startswith(self.redirect_uri):
                break

            url = urljoin('https://identity.vwgroup.io', url)

            if 'terms-and-conditions' in url:
                if self.accept_terms_on_login:
                    url = self._handle_consent_form(url)
                else:
                    raise AuthentificationError(f'It seems like you need to accept the terms and conditions. '
                                              f'Try to visit the URL "{url}" or log into smartphone app.')

            response = self.websession.get(url, allow_redirects=False)
            if response.status_code == requests.codes['internal_server_error']:
                raise RetrievalError('Temporary server error during login')

            if 'Location' not in response.headers:
                if 'consent' in url:
                    raise AuthentificationError('Could not find Location in headers, probably due to missing consent. Try visiting: ' + url)
                raise APICompatibilityError('Forwarding without Location in headers')

            url = response.headers['Location']

        return url.replace(self.redirect_uri + '#', 'https://egal?')

    def _get_login_form(self, url: str) -> HTMLFormParser:
        while True:
            response = self.websession.get(url, allow_redirects=False)
            if response.status_code == requests.codes['ok']:
                break

            if response.status_code in (requests.codes['found'], requests.codes['see_other']):
                if 'Location' not in response.headers:
                    raise APICompatibilityError('Forwarding without Location in headers')

                url = response.headers['Location']
                continue

            raise APICompatibilityError(f'Retrieving login page was not successful, '
                                        f'status code: {response.status_code}')

        email_form = HTMLFormParser(form_id='emailPasswordForm')
        email_form.feed(response.text)

        if not email_form.target or not all(x in email_form.data for x in ['_csrf', 'relayState', 'hmac', 'email']):
            raise APICompatibilityError('Could not find all required input fields on login page')

        return email_form

    def _get_password_form(self, url: str, data: Dict[str, Any]) -> CredentialsFormParser:
        response = self.websession.post(url, data=data, allow_redirects=True)
        if response.status_code != requests.codes['ok']:
            raise APICompatibilityError(f'Retrieving credentials page was not successful, '
                                        f'status code: {response.status_code}')

        credentials_form = CredentialsFormParser()
        credentials_form.feed(response.text)

        if not credentials_form.target or not all(x in credentials_form.data for x in ['relayState', 'hmac', '_csrf']):
            raise APICompatibilityError('Could not find all required input fields on credentials page')

        if credentials_form.data.get('error', None) is not None:
            if credentials_form.data['error'] == 'validator.email.invalid':
                raise AuthentificationError('Error during login, email invalid')
            raise AuthentificationError(f'Error during login: {credentials_form.data["error"]}')

        if 'errorCode' in credentials_form.data:
            raise AuthentificationError('Error during login, is the username correct?')

        if credentials_form.data.get('registerCredentialsPath', None) == 'register':
            raise AuthentificationError(f'Error during login, account {self.session_user.username} does not exist')

        return credentials_form

    def _handle_login(self, url: str, data: Dict[str, Any]) -> str:
        response: requests.Response = self.websession.post(url, data=data, allow_redirects=False)

        if response.status_code == requests.codes['internal_server_error']:
            raise RetrievalError('Temporary server error during login')

        if response.status_code not in (requests.codes['found'], requests.codes['see_other']):
            raise APICompatibilityError(f'Forwarding expected (status code 302), '
                                        f'but got status code {response.status_code}')

        if 'Location' not in response.headers:
            raise APICompatibilityError('Forwarding without Location in headers')

        params: Dict[str, str] = dict(parse_qsl(urlsplit(response.headers['Location']).query))

        if 'error' in params and params['error']:
            error_messages: Dict[str, str] = {
                'login.errors.password_invalid': 'Password is invalid',
                'login.error.throttled': 'Login throttled, probably too many wrong logins. You have to wait '
                                         'a few minutes until a new login attempt is possible'
            }

            raise AuthentificationError(error_messages.get(params['error'], params['error']))

        if 'userId' not in params or not params['userId']:
            if 'updated' in params and params['updated'] == 'dataprivacy':
                raise AuthentificationError('You have to login at myvolkswagen.de and accept the terms and conditions')
            raise APICompatibilityError('No user ID provided')

        self.userId = params['userId']
        return response.headers['Location']

    def _handle_consent_form(self, url: str) -> str:
        response = self.websession.get(url, allow_redirects=False)
        if response.status_code == requests.codes['internal_server_error']:
            raise RetrievalError('Temporary server error during login')

        tc_form = TermsAndConditionsFormParser()
        tc_form.feed(response.text)

        url = urlparse(response.url)._replace(query='').geturl()

        response = self.websession.post(url, data=tc_form.data, allow_redirects=False)
        if response.status_code == requests.codes['internal_server_error']:
            raise RetrievalError('Temporary server error during login')

        if response.status_code not in (requests.codes['found'], requests.codes['see_other']):
            raise APICompatibilityError('Forwarding expected (status code 302), '
                                        f'but got status code {response.status_code}')

        if 'Location' not in response.headers:
            raise APICompatibilityError('Forwarding without Location in headers')

        return response.headers['Location']
