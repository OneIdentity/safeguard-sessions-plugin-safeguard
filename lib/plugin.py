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
from safeguard.sessions.plugin.credentialstore_plugin import CredentialStorePlugin
from safeguard.sessions.plugin.plugin_base import cookie_property, session_cookie_property
from textwrap import dedent

from .safeguard import SafeguardClientFactory, SafeguardException

DEFAULT_CONFIG = dedent(
    """
    [safeguard]
    check_host_name=yes

    [assets]
    generator=ip, hostname, domain, domain_asset_mapping_with_suffix

    [safeguard-password-authentication]
    provider=local
    use_credential=gateway
"""
)


class SafeguardPlugin(CredentialStorePlugin):
    def __init__(self, configuration, safeguard_client_factory=None):
        super().__init__(
            configuration, defaults=DEFAULT_CONFIG, configuration_section="safeguard-password-authentication"
        )
        self._safeguard_client_factory = safeguard_client_factory

    def do_get_password_list(self):
        return self._get_credential("password")

    def do_get_remote_app_credentials(self):
        self.logger.info(
            "Trying to checkout password for RemoteApp Injection. Asset: %s, Account: %s",
            self.remote_app_asset,
            self.remote_app_account
        )
        try:
            credential = self._get_credential_for_asset("password", self.remote_app_asset, self.remote_app_account)
            return {"passwords": [credential]}
        except SafeguardException as exc:
            self.logger.error(
                "Error checking out %s for %s@%s: '%s'", "password",
                self.remote_app_account,
                self.remote_app_asset,
                exc
            )
            return None

    def domain_asset_mapping_with_suffix(self):
        server_domain = (
            f"{self.connection.server_domain}.{self.domain_suffix}"
            if self.domain_suffix
            else self.connection.server_domain
        )
        return self.plugin_configuration.get("domain_asset_mapping", server_domain)

    def _get_credential(self, credential_type):
        self.logger.info("Trying to check out %s for %s@%s", credential_type, self.account, self.asset)
        try:
            credential = self._get_credential_for_asset(credential_type)
            if credential_type == "password":
                return {"passwords": [credential]}
            else:
                ssh_key_type = "ssh-rsa"  # NOTE: ssh key type is hard-coded here...
                return {"private_keys": [(ssh_key_type, credential)]}
        except SafeguardException as exc:
            self.logger.error("Error checking out %s for %s@%s: '%s'", credential_type, self.account, self.asset, exc)

    def _get_credential_for_asset(self, credential_type, asset=None, account=None):
        c_asset = asset or self.asset
        c_account = account or self.account
        safeguard = self._make_safeguard_instance()
        account_id = safeguard.get_account(c_asset, c_account)
        credential, access_request_id = safeguard.checkout_credential(account_id, credential_type)
        self.logger.info("Found %s for %s@%s", credential_type, c_account, c_asset)
        self.access_request_id.append(access_request_id)
        self.access_token = safeguard.access_token
        return credential

    def do_check_in_credential(self):
        try:
            self.logger.debug("Checking in credential")
            if not self.access_request_id:
                raise SafeguardException("Missing access_request_id")
            safeguard = self._make_safeguard_instance()
            [safeguard.checkin_credential(request_id) for request_id in self.access_request_id]
        except SafeguardException as exc:
            self.logger.error("Error checking in credential %s", exc)
            raise exc

    def _make_safeguard_instance(self):
        if not self._safeguard_client_factory:
            self._safeguard_client_factory = SafeguardClientFactory.from_config(self.plugin_configuration)

        safeguard = self._safeguard_client_factory.new_instance(
            access_token=self.access_token, session_access_token=self.token, **self._get_auth_credentials()
        )
        return safeguard

    def _get_auth_credentials(self):
        credential_type = self.plugin_configuration.getienum(
            self._configuration_section, "use_credential", ("explicit", "gateway", "token")
        )
        return (
            {"auth_username": self.authentication_username, "auth_password": self.authentication_password}
            if credential_type in ("explicit", "gateway")
            else {"auth_username": None, "auth_password": None}
        )

    @cookie_property
    def access_request_id(self):
        return []

    @cookie_property
    def access_token(self):
        return None

    @session_cookie_property
    def token(self):
        return None
