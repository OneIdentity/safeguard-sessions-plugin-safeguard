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
from safeguard.sessions.plugin_impl.test_utils.plugin import (
    assert_plugin_hook_result,
    check_that_data_is_serializable,
    minimal_parameters,
    update_cookies,
)


def test_checkout_password_with_gateway_credentials(gateway_config, safeguard_lock, generate_params):
    plugin = SafeguardPlugin(gateway_config)
    params = generate_params()

    checkout_result = plugin.get_password_list(**deepcopy(params))

    check_that_data_is_serializable(checkout_result)
    update_cookies(params, checkout_result)
    plugin.authentication_completed(**minimal_parameters(params))
    plugin.session_ended(**minimal_parameters(params))

    checkout_result_cookie = checkout_result["cookie"]
    assert "access_request_id" in checkout_result_cookie
    assert "access_token" in checkout_result_cookie
    assert checkout_result["passwords"]  # not None and has at least 1 element


def test_checkout_password_with_explicit_credentials(explicit_config, safeguard_lock, generate_params):
    plugin = SafeguardPlugin(explicit_config)
    params = generate_params()

    checkout_result = plugin.get_password_list(**deepcopy(params))

    check_that_data_is_serializable(checkout_result)
    update_cookies(params, checkout_result)
    plugin.authentication_completed(**minimal_parameters(params))
    plugin.session_ended(**minimal_parameters(params))

    checkout_result_cookie = checkout_result["cookie"]
    assert "access_request_id" in checkout_result_cookie
    assert "access_token" in checkout_result_cookie
    assert checkout_result["passwords"]  # not None and has at least 1 element


def test_checkout_password_with_token(token_config, safeguard_lock, safeguard_client, generate_params):
    plugin = SafeguardPlugin(token_config)
    safeguard_client.authenticate()
    params = generate_params(session_cookie={"token": safeguard_client.access_token})

    checkout_result = plugin.get_password_list(**deepcopy(params))

    check_that_data_is_serializable(checkout_result)
    update_cookies(params, checkout_result)
    plugin.authentication_completed(**minimal_parameters(params))
    plugin.session_ended(**minimal_parameters(params))

    checkout_result_cookie = checkout_result["cookie"]
    assert "access_request_id" in checkout_result_cookie
    assert "access_token" in checkout_result_cookie
    assert checkout_result["passwords"]  # not None and has at least 1 element


def test_get_password_list_returns_the_correct_response(explicit_config, dummy_sg_client_factory, generate_params):
    plugin = SafeguardPlugin(explicit_config, safeguard_client_factory=dummy_sg_client_factory)
    params = generate_params()
    result = plugin.get_password_list(**deepcopy(params))

    assert_plugin_hook_result(
        result,
        {
    "cookie": {"access_token": "the_access_token", "access_request_id": ["the_access_request_id"]},
            "passwords": ["the_password"],
        },
    )


def test_raises_exception_if_access_request_id_is_not_presented(explicit_config, dummy_sg_client_factory):
    plugin = SafeguardPlugin(explicit_config, safeguard_client_factory=dummy_sg_client_factory)
    with pytest.raises(SafeguardException) as exc_info:
        plugin.session_ended(cookie={"account": "x"}, session_cookie={}, session_id="the_session_id")
    assert exc_info.match("Missing access_request_id")


class SaveAssets(SafeguardPlugin):
    def __init__(self, configuration, safeguard_client_factory):
        super().__init__(configuration, safeguard_client_factory)
        self.test_asset_list = []

    def do_get_password_list(self):
        self.test_asset_list.append(self.asset)


def test_assets_suffix(explicit_config, dummy_sg_client_factory, generate_params):
    config = dedent(
        """
        [domain_asset_mapping]
        bar.baz=acme.com

        [assets]
        domain_suffix=baz
    """
    )

    plugin = SaveAssets(config, dummy_sg_client_factory)
    params = generate_params(server_hostname="foo.bar", server_domain="bar")

    plugin.get_password_list(**deepcopy(params))

    assert plugin.test_asset_list == ["1.1.1.1", "foo.bar.baz", "bar.baz", "acme.com"]
