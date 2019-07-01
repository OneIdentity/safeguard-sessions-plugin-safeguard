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
import pytest
import time
import urllib.error

from ..safeguard import Account, HttpClient, SafeguardClient, SafeguardException


@pytest.fixture
def safeguard_address(site_parameters):
    return site_parameters['address']


@pytest.fixture
def auth_username(site_parameters):
    return site_parameters['username']


@pytest.fixture
def auth_password(site_parameters):
    return site_parameters['password']


@pytest.fixture
def target_host(site_parameters):
    return site_parameters['target_host']


@pytest.fixture
def target_username(site_parameters):
    return site_parameters['target_username']


@pytest.fixture
def safeguard_config(safeguard_address):
    return """
[safeguard]
address={}
""".format(safeguard_address)


@pytest.fixture
def explicit_config(safeguard_config, auth_username, auth_password):
    return safeguard_config + """
ip_resolving=no
[safeguard-password-authentication]
use_credential=explicit
username={username}
password={password}
""".format(username=auth_username, password=auth_password)


@pytest.fixture
def gateway_config(safeguard_config):
    return safeguard_config + """
[safeguard-password-authentication]
use_credential=gateway
"""


@pytest.fixture
def token_config(safeguard_config):
    return safeguard_config + """
[safeguard-password-authentication]
use_credential=token
"""


@pytest.fixture
def safeguard_lock(vcr):
    yield
    # Wait for Safeguard to change password after check-in
    # When we are recording
    if vcr.record_mode == 'all':
        time.sleep(15)


@pytest.fixture
def safeguard_client(safeguard_address, auth_username, auth_password):
    return SafeguardClient(
        http_client=HttpClient(ca_cert=None, check_hostname=False),
        address=safeguard_address,
        provider='local',
        auth_username=auth_username,
        auth_password=auth_password
    )


class DummySafeguardClient(object):
    def __init__(self, address='the_address', access_token='the_access_token', asset_id='the_asset_id',
                 account_id='the_account_id', password='the_password', access_request_id='the_access_request_id'):
        self.address = address
        self.__access_token = access_token
        self.__asset_id = asset_id
        self.__account_id = account_id
        self.__password = password
        self.__access_request_id = access_request_id

    @property
    def access_token(self):
        return self.__access_token

    def get_account(self, asset_identifier, account_name):
        if asset_identifier != '2.2.2.2':
            return Account(self.__asset_id, self.__account_id)
        else:
            raise SafeguardException("Unknown asset {}".format(asset_identifier))

    def checkout_credential(self, account, credential_type):
        return self.__password, self.__access_request_id

    def checkin_credential(self, access_request_id):
        pass


class UnreachableSafeguardClient(object):
    ERROR = urllib.error.URLError("[Errno 110] Connection timed out")

    def __init__(self, address='the_address'):
        self.address = address

    @property
    def access_token(self):
        return None

    def get_account(self, asset_identifier, account_name):
        raise self.ERROR

    def checkout_credential(self, account, credential_type):
        raise self.ERROR

    def checkin_credential(self, access_request_id):
        raise self.ERROR


class DummySafeguardClientFactory(object):
    def new_instance(self, *args, **kwargs):
        return DummySafeguardClient()


@pytest.fixture
def dummy_sg_client_factory():
    return DummySafeguardClientFactory()
