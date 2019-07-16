#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from collections import namedtuple
import json
from safeguard.sessions.plugin import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request


class SafeguardException(Exception):
    pass


class HttpClient(object):
    def __init__(self, ca_cert=None, check_hostname=True):
        self.__ssl_context = self.__create_ssl_context(ca_cert, check_hostname)

    @staticmethod
    def __create_ssl_context(ca_cert, check_hostname):
        ssl_context = ssl.create_default_context(cadata=ca_cert)
        if ca_cert is None:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        else:
            ssl_context.check_hostname = check_hostname
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        return ssl_context

    def make_request(self, url, headers={}, data=None):
        if data:
            data = json.dumps(data).encode("utf-8")
        request = urllib.request.Request(url=url, headers=headers, data=data)
        if data:
            request.add_header('Content-Type', 'application/json; charset=utf-8')
        return urllib.request.urlopen(request, context=self.__ssl_context)


class SafeguardClientFactory(object):
    def __init__(self, addresses, check_host_name, ca, credential_source, provider, auth_username, auth_password):
        self._addresses = addresses
        self._check_host_name = check_host_name
        self._ca = ca
        self._credential_source = credential_source
        self._provider = provider
        self._auth_username = auth_username
        self._auth_password = auth_password

        self.__logger = logging.get_logger(__name__)

    def new_instance(self, access_token=None, session_access_token=None, gateway_username=None, gateway_password=None):
        if access_token is not None:
            self.__logger.debug("Using exisiting access token to authenticate")
            auth_params = dict(access_token=access_token)
        elif self._credential_source == 'token':
            self.__logger.debug("Using existing access token from session to authenticate")
            if session_access_token is None:
                raise SafeguardException('Access token is missing from session cookie')
            else:
                auth_params = dict(access_token=session_access_token)
        elif self._credential_source == 'explicit':
            self.__logger.debug("Using explictly configured proxy user to authenticate")
            if self._auth_username is None or self._auth_password is None:
                raise SafeguardException('Missing username or password')
            else:
                auth_params = dict(auth_username=self._auth_username, auth_password=self._auth_password)
        elif self._credential_source == 'gateway':
            self.__logger.debug("Using gateway user to authenticate")
            if gateway_username is None or gateway_password is None:
                raise SafeguardException('Missing gateway credential')
            else:
                auth_params = dict(auth_username=gateway_username, auth_password=gateway_password)
        else:
            raise SafeguardException('Invalid credential source: {}'.format(self._credential_source))

        http_client = HttpClient(ca_cert=self._ca, check_hostname=self._check_host_name)
        clients = [
            SafeguardClient(
                http_client=http_client,
                address=address,
                provider=self._provider,
                **auth_params
            ) for address in self._addresses
        ]

        return SafeguardClusterClient(clients)

    @classmethod
    def from_config(cls, config):
        def compatible_auth_parameter_get(parameter):
            return config.get('safeguard', parameter) or config.get('safeguard-password-authentication', parameter)

        return cls(
            addresses=config.get('safeguard', 'address').split(','),
            check_host_name=config.getboolean('safeguard', 'check_host_name'),
            ca=config.get('safeguard', 'ca'),
            credential_source=compatible_auth_parameter_get('use_credential'),
            provider=compatible_auth_parameter_get('provider'),
            auth_username=compatible_auth_parameter_get('username'),
            auth_password=compatible_auth_parameter_get('password')
        )


Account = namedtuple('Account', ('asset_id', 'id'))


def with_authentication(method):
    def wrapper(self, *args, **kwargs):
        self.authenticate()
        try:
            return method(self, *args, **kwargs)
        except urllib.error.HTTPError as err:
            if err.code == 401:  # Unauthorized
                self.authenticate(force=True)
                return method(self, *args, **kwargs)
            else:
                error = json.loads(err.fp.read())
                raise SafeguardException("Request failed; Details: {} {}".format(err, error))
    return wrapper


def lowercase(value):
    return value and value.lower()


class SafeguardClient(object):
    CONTENT_TYPE_JSON = {'content-type': 'application/json'}

    def __init__(self, http_client, address, provider='local', auth_username=None, auth_password=None,
                 access_token=None):
        self.__logger = logging.get_logger(__name__)
        self.address = address
        self.http_client = http_client
        self._provider = provider
        self._auth_username = auth_username
        self._auth_password = auth_password
        self._access_token = access_token

    @property
    def access_token(self):
        return self._access_token

    def authenticate(self, force=False):
        if force:
            self._access_token = None

        if self._access_token is None:
            self._access_token = self._get_safeguard_token()

    def _get_rsts_token(self):
        auth_data = {
            'username': self._auth_username,
            'password': self._auth_password,
            'grant_type': 'password',
            'scope': 'rsts:sts:primaryproviderid:{}'.format(self._provider)
        }

        self.__logger.info(
            "Safeguard password authentication with username={} provider={}".format(self._auth_username, self._provider)
        )

        url = 'https://{}/RSTS/oauth2/token'.format(self.address)
        try:
            response = self._do_request(url=url, data=auth_data)
        except urllib.error.HTTPError as err:
            raise SafeguardException(
                "rSTS (OAuth2) authentication failed. Details: {} {}".format(err, err.read().decode("utf-8"))
            )
        else:
            if not response['success']:
                raise SafeguardException("rSTS (OAuth2) authentication failed. Details: {}".format(response))

            return response['access_token']

    def _get_safeguard_token(self):
        rsts_token = self._get_rsts_token()
        auth_data = {
            'StsAccessToken': rsts_token
        }
        url = self._build_url('Token/LoginResponse')
        headers = self._build_authorization_header(rsts_token)
        headers.update(self.CONTENT_TYPE_JSON)
        try:
            response = self._do_request(url=url, headers=headers, data=auth_data)
        except urllib.error.HTTPError as err:
            raise SafeguardException("API token request failed. Details: {} {}".format(err, err.read().decode("utf-8")))
        else:
            if response['Status'] != 'Success':
                raise SafeguardException("API token request failed. Details: {}".format(response))

            return response['UserToken']

    def get_account(self, asset_identifier, account_name):
        asset_id = self._find_asset(asset_identifier)
        account_id = self._find_account(asset_id, account_name)
        return Account(asset_id, account_id)

    def _list_assets(self):
        return self._get('Me/RequestableAssets')

    def _find_asset(self, asset_identifier):
        assets = self._list_assets()
        for asset in assets:
            if lowercase(asset_identifier) in (lowercase(asset['NetworkAddress']), lowercase(asset['Name'])):
                return asset['Id']
        raise SafeguardException("Cannot find asset '{}'".format(asset_identifier))

    def _list_accounts(self, asset_id):
        return self._get('Me/RequestableAssets/{}/Accounts'.format(asset_id))

    def _find_account(self, asset_id, account_name):
        accounts = self._list_accounts(asset_id)
        for account in accounts:
            if lowercase(account_name) == lowercase(account['Name']):
                return account['Id']
        raise SafeguardException("Cannot find account '{}'".format(account_name))

    def _make_access_request(self, account):
        return self._post('AccessRequests', {
            "SystemId": account.asset_id,
            "AccountId": account.id,
            "AccessRequestType": "Password",
        })

    def _check_out_password(self, access_request_id):
        return self._post('AccessRequests/{}/CheckOutPassword'.format(access_request_id))

    def checkout_credential(self, account, credential_type):
        if credential_type != 'password':
            raise SafeguardException("Only password credential type is supported: {}".format(credential_type))

        # FIXME: reuse previous access request ID?
        access_request = self._make_access_request(account)
        access_request_id = access_request['Id']
        password = self._check_out_password(access_request_id)
        return password, access_request_id

    def checkin_credential(self, access_request_id):
        self._post('AccessRequests/{}/CheckIn'.format(access_request_id))

    @with_authentication
    def _get(self, resource, parameters=()):
        url = self._build_url(resource, parameters)
        headers = self._build_authorization_header(self._access_token)
        return self._do_request(url=url, headers=headers)

    @with_authentication
    def _post(self, resource, post_data={}, parameters=()):
        url = self._build_url(resource, parameters)
        headers = self._build_authorization_header(self._access_token)
        headers.update(self.CONTENT_TYPE_JSON)
        return self._do_request(url=url, headers=headers, data=post_data)

    def _do_request(self, url, headers={}, data=None):
        response = self.http_client.make_request(url=url, headers=headers, data=data)
        raw_result = response.read()
        self.__logger.debug("Got response: %s", raw_result)
        return json.loads(raw_result)

    @staticmethod
    def _build_authorization_header(token):
        return {'authorization': 'Bearer {}'.format(token)}

    def _build_url(self, resource, parameters=()):
        url = 'https://{}/service/core/v2/{}'.format(self.address, resource)
        if parameters:
            url += '/?' + urllib.parse.urlencode(parameters)
        return url


class SafeguardClusterClient(object):
    def __init__(self, safeguard_clients):
        self.__logger = logging.get_logger(__name__)
        self.clients = safeguard_clients
        self.__access_token = None

    def __try_with_clients(self, action):
        for client in self.clients:
            try:
                result = action(client)
            except urllib.error.URLError as ex:
                self.__logger.warning("Cluster node unreachable: %s. Details: %s", client.address, ex)
            else:
                self.__access_token = client.access_token
                return result
        self.__logger.error("Cluster unreachable")
        raise SafeguardException("Cluster unreachable")

    @property
    def access_token(self):
        return self.__access_token

    def get_account(self, asset_identifier, account_name):
        return self.__try_with_clients(lambda client: client.get_account(asset_identifier, account_name))

    def checkout_credential(self, account, credential_type):
        return self.__try_with_clients(lambda client: client.checkout_credential(account, credential_type))

    def checkin_credential(self, access_request_id):
        return self.__try_with_clients(lambda client: client.checkin_credential(access_request_id))
