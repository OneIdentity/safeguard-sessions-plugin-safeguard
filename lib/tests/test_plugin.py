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
import unittest.mock
from ..plugin import SafeguardPlugin
from ..safeguard import SafeguardException


@pytest.mark.interactive
def test_checkout_password_with_gateway_credentials(gateway_config, safeguard_lock, target_username, target_host,
                                                    auth_username, auth_password):
    plugin = SafeguardPlugin(gateway_config)
    session_id = 'the_session_id'
    checkout_result = plugin.get_password_list(session_id=session_id,
                                               cookie={},
                                               target_username=target_username,
                                               target_host=target_host,
                                               gateway_username=auth_username,
                                               gateway_password=auth_password)
    checkout_result_cookie = checkout_result['cookie']
    plugin.authentication_completed(session_id, {
        'access_request_id': checkout_result_cookie['access_request_id'],
        'access_token': checkout_result_cookie['access_token']})

    assert 'access_request_id' in checkout_result_cookie
    assert 'access_token' in checkout_result_cookie
    assert checkout_result['passwords']  # not None and has at least 1 element


@pytest.mark.interactive
def test_checkout_password_with_explicit_credentials(explicit_config, safeguard_lock, target_username, target_host):
    plugin = SafeguardPlugin(explicit_config)
    session_id = 'the_session_id'
    checkout_result = plugin.get_password_list(session_id=session_id,
                                               cookie={},
                                               target_username=target_username,
                                               target_host=target_host)
    checkout_result_cookie = checkout_result['cookie']
    plugin.authentication_completed(session_id, {
        'access_request_id': checkout_result_cookie['access_request_id'],
        'access_token': checkout_result_cookie['access_token']})

    assert 'access_request_id' in checkout_result_cookie
    assert 'access_token' in checkout_result_cookie
    assert checkout_result['passwords']  # not None and has at least 1 element


@pytest.mark.interactive
def test_checkout_password_with_token(token_config, safeguard_lock, safeguard_client, target_username, target_host):
    plugin = SafeguardPlugin(token_config)
    session_id = 'the_session_id'
    safeguard_client.authenticate()
    session_cookie = {
        'token': safeguard_client.access_token
    }
    checkout_result = plugin.get_password_list(session_id=session_id,
                                               cookie={},
                                               target_username=target_username,
                                               target_host=target_host,
                                               session_cookie=session_cookie)
    checkout_result_cookie = checkout_result['cookie']
    plugin.authentication_completed(session_id, {
        'access_request_id': checkout_result_cookie['access_request_id'],
        'access_token': checkout_result_cookie['access_token']})

    assert 'access_request_id' in checkout_result_cookie
    assert 'access_token' in checkout_result_cookie
    assert checkout_result['passwords']  # not None and has at least 1 element


def test_get_password_list_returns_the_correct_response(explicit_config, dummy_sg_client_factory):
    plugin = SafeguardPlugin(explicit_config, safeguard_client_factory=dummy_sg_client_factory)
    result = plugin.get_password_list(session_id='the_session_id',
                                      cookie={},
                                      target_username='u1',
                                      target_host='h1')
    expected_result = {
        'cookie': {
            'access_token': 'the_access_token',
            'access_request_id': 'the_access_request_id',
            'account': ('the_asset_id', 'the_account_id')
        },
        'passwords': ['the_password']
    }
    assert result == expected_result


def test_raises_exception_if_access_request_id_is_not_presented(explicit_config, dummy_sg_client_factory):
    plugin = SafeguardPlugin(explicit_config, safeguard_client_factory=dummy_sg_client_factory)
    with pytest.raises(SafeguardException) as exc_info:
        plugin.authentication_completed('the_session_id', {})
    assert 'Missing access_request_id' in str(exc_info)


def test_session_end_should_reply_with_cookie(explicit_config, dummy_sg_client_factory):
    plugin = SafeguardPlugin(explicit_config, safeguard_client_factory=dummy_sg_client_factory)
    result = plugin.session_ended('the_session_id', {'credential_checked_in': True})
    assert result == {'cookie': {'credential_checked_in': True}}


def test_does_not_resolve_hosts_when_resolving_turned_off(explicit_config, dummy_sg_client_factory):
    with unittest.mock.patch('lib.plugin.HostResolver.resolve_hosts_by_ip') as m:
        plugin = SafeguardPlugin(explicit_config, safeguard_client_factory=dummy_sg_client_factory)
        plugin.get_password_list(session_id='the_session_id',
                                 cookie={},
                                 target_username='u1',
                                 target_host='1.1.1.1')
        m.assert_not_called()


def test_resolve_hosts_when_configured(explicit_config, dummy_sg_client_factory):
    enabled_resolving = explicit_config.replace('ip_resolving=no', 'ip_resolving=yes')
    with unittest.mock.patch('lib.plugin.HostResolver.resolve_hosts_by_ip') as m:
        plugin = SafeguardPlugin(enabled_resolving, safeguard_client_factory=dummy_sg_client_factory)
        plugin.get_password_list(session_id='the_session_id',
                                 cookie={},
                                 target_username='u1',
                                 target_host='1.1.1.1')
        m.assert_called_once_with('1.1.1.1')
