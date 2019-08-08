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
from copy import deepcopy
import pytest
from textwrap import dedent
import unittest.mock
from ..plugin import SafeguardPlugin
from ..safeguard import SafeguardException
from safeguard.sessions.plugin_impl.test_utils.plugin import (assert_plugin_hook_result,
    check_that_data_is_serializable, minimal_parameters, update_cookies)


def test_checkout_password_with_gateway_credentials(gateway_config, safeguard_lock, target_username, target_host,
                                                    auth_username, auth_password):
    plugin = SafeguardPlugin(gateway_config)

    params = dict(
        session_id='the_session_id',
        cookie={},
        session_cookie={},
        target_username=target_username,
        target_host=target_host,
        gateway_username=auth_username,
        gateway_password=auth_password,
        protocol='SSH'
    )

    checkout_result = plugin.get_password_list(**deepcopy(params))

    check_that_data_is_serializable(checkout_result)
    update_cookies(params, checkout_result)
    plugin.authentication_completed(**minimal_parameters(params))

    checkout_result_cookie = checkout_result['cookie']
    assert 'access_request_id' in checkout_result_cookie
    assert 'access_token' in checkout_result_cookie
    assert checkout_result['passwords']  # not None and has at least 1 element


def test_checkout_password_with_explicit_credentials(explicit_config, safeguard_lock, target_username, target_host):
    plugin = SafeguardPlugin(explicit_config)

    params=dict(
        cookie={},
        session_cookie={},
        session_id='the_session_id',
        target_username=target_username,
        target_host=target_host,
        protocol='SSH'
    )

    checkout_result = plugin.get_password_list(**deepcopy(params))

    check_that_data_is_serializable(checkout_result)
    update_cookies(params, checkout_result)
    plugin.authentication_completed(**minimal_parameters(params))

    checkout_result_cookie = checkout_result['cookie']
    assert 'access_request_id' in checkout_result_cookie
    assert 'access_token' in checkout_result_cookie
    assert checkout_result['passwords']  # not None and has at least 1 element


def test_checkout_password_with_token(token_config, safeguard_lock, safeguard_client, target_username, target_host):
    plugin = SafeguardPlugin(token_config)
    safeguard_client.authenticate()

    params = dict(
        cookie={},
        session_cookie={'token': safeguard_client.access_token},
        session_id='the_session_id',
        target_username=target_username,
        target_host=target_host,
        protocol='SSH'
    )

    checkout_result = plugin.get_password_list(**deepcopy(params))

    check_that_data_is_serializable(checkout_result)
    update_cookies(params, checkout_result)
    plugin.authentication_completed(**minimal_parameters(params))

    checkout_result_cookie = checkout_result['cookie']
    assert 'access_request_id' in checkout_result_cookie
    assert 'access_token' in checkout_result_cookie
    assert checkout_result['passwords']  # not None and has at least 1 element


def test_get_password_list_returns_the_correct_response(explicit_config, dummy_sg_client_factory):
    plugin = SafeguardPlugin(explicit_config, safeguard_client_factory=dummy_sg_client_factory)
    result = plugin.get_password_list(
        session_id='the_session_id',
        cookie={},
        session_cookie={},
        target_username='u1',
        target_host='h1',
        protocol='SSH'
    )

    assert_plugin_hook_result(result, {
        'cookie': {
            'access_token': 'the_access_token',
            'access_request_id': 'the_access_request_id',
        },
        'passwords': ['the_password']
    })


def test_raises_exception_if_access_request_id_is_not_presented(explicit_config, dummy_sg_client_factory):
    plugin = SafeguardPlugin(explicit_config, safeguard_client_factory=dummy_sg_client_factory)
    with pytest.raises(SafeguardException) as exc_info:
        plugin.session_ended(
            cookie={'account': 'x'},
            session_cookie={},
            session_id='the_session_id'
        )
    assert 'Missing access_request_id' in str(exc_info)


def test_does_not_resolve_hosts_when_resolving_turned_off(explicit_config, dummy_sg_client_factory):
    with unittest.mock.patch('lib.plugin.HostResolver.resolve_hosts_by_ip') as m:
        plugin = SafeguardPlugin(explicit_config, safeguard_client_factory=dummy_sg_client_factory)
        plugin.get_password_list(
            session_id='the_session_id',
            cookie={},
            session_cookie={},
            target_username='u1',
            target_host='2.2.2.2',
            protocol='SSH'
        )
        m.assert_not_called()


def test_resolve_hosts_when_configured(explicit_config, dummy_sg_client_factory):
    enabled_resolving = explicit_config.replace('ip_resolving=no', 'ip_resolving=yes')
    with unittest.mock.patch('lib.plugin.HostResolver.resolve_hosts_by_ip') as m:
        plugin = SafeguardPlugin(enabled_resolving, safeguard_client_factory=dummy_sg_client_factory)
        plugin.get_password_list(
            session_id='the_session_id',
            cookie={},
            session_cookie={},
            target_username='u1',
            target_host='2.2.2.2',
            protocol='SSH'
        )

        m.assert_called_once_with('2.2.2.2')


class SaveAssets(SafeguardPlugin):
    def __init__(self, configuration, safeguard_client_factory):
        super().__init__(configuration, safeguard_client_factory)
        self.test_asset_list = []

    def do_get_password_list(self):
        self.test_asset_list.append(self.asset)


def test_assets(explicit_config, dummy_sg_client_factory):
    config = dedent("""
        [domain_asset_mapping]
        foo.bar = acme.com
    """)

    plugin = SaveAssets(config, dummy_sg_client_factory)

    plugin.get_password_list(
        cookie={},
        session_cookie={},
        target_username='u1',
        target_host='1.1.1.1',
        target_domain='foo.bar',
        protocol='SSH'
    )

    assert plugin.test_asset_list == ['1.1.1.1', 'foo.bar', 'acme.com']


def test_assets_suffix(explicit_config, dummy_sg_client_factory):
    config = dedent("""
        [safeguard]
        domain_suffix = net

        [domain_asset_mapping]
        foo.bar.net = acme.com
    """)



    plugin = SaveAssets(config, dummy_sg_client_factory)

    plugin.get_password_list(
        cookie={},
        session_cookie={},
        target_username='u1',
        target_host='1.1.1.1',
        target_domain='foo.bar',
        protocol='SSH'
    )

    assert plugin.test_asset_list == ['1.1.1.1', 'foo.bar.net', 'acme.com']
