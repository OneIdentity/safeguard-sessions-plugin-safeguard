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
from safeguard.sessions.plugin.host_resolver import HostResolver
from safeguard.sessions.plugin.credentialstore_plugin import CredentialStorePlugin
from safeguard.sessions.plugin.plugin_base import cookie_property, session_cookie_property
from textwrap import dedent

from .safeguard import SafeguardClientFactory, SafeguardException

DEFAULT_CONFIG = dedent("""
    [safeguard]
    ip_resolving=no
    check_host_name=yes
    
    [safeguard_password_authentication]
    provider=local
    use_credential=gateway
""")


class SafeguardPlugin(CredentialStorePlugin):

    def __init__(self, configuration, safeguard_client_factory=None):
        super().__init__(configuration, DEFAULT_CONFIG)
        self._safeguard_client_factory = (safeguard_client_factory or
                                          SafeguardClientFactory.from_config(self.plugin_configuration))
        self._domain_suffix = self.plugin_configuration.get('safeguard', 'domain_suffix')

    def _extract_assets(self):
        target_domain = self.connection.target_domain
        target_host = self.connection.target_ip
        lookup_identifiers = [target_host]

        if self.plugin_configuration.getboolean('safeguard', 'ip_resolving'):
            resolved_hosts = HostResolver.from_config(self.plugin_configuration).resolve_hosts_by_ip(target_host)
            lookup_identifiers.extend(resolved_hosts)

        if target_domain:
            if self._domain_suffix:
                target_domain = '%s.%s' % (target_domain, self._domain_suffix)
            lookup_identifiers.append(target_domain)

            if self.plugin_configuration.get('domain_asset_mapping', target_domain):
                lookup_identifiers.append(self.plugin_configuration.get('domain_asset_mapping', target_domain))
        return lookup_identifiers

    def do_get_password_list(self):
        return self._get_credential('password')

    def do_get_private_key_list(self):
        return self._get_credential('ssh-key')

    def _get_credential(self, credential_type):
        target_username = self.connection.target_username

        for asset in self.assets:
            self.logger.info('Trying to check out % for %s@%s', credential_type, target_username, asset)
            try:
                credential = self._get_credential_for_asset(credential_type, asset)
                if credential_type == 'password':
                    return {'passwords': [credential]}
                else:
                    ssh_key_type = 'ssh-rsa'  # NOTE: ssh key type is hard-coded here...
                    return {'private_keys': [(ssh_key_type, credential)]}
            except SafeguardException as exc:
                self.logger.error("Error checking out %s for %s@%s: '%s'", credential_type, target_username, asset, exc)

        self.logger.error('Failed to check out %s for %s', credential_type, target_username)

    def _get_credential_for_asset(self, credential_type, asset):
        safeguard = self._make_safeguard_instance()
        account_id = safeguard.get_account(asset, self.connection.target_username)
        credential, access_request_id = safeguard.checkout_credential(account_id, credential_type)
        self.logger.info("Found %s for %s@%s", credential_type, self.connection.target_username, asset)
        self.access_request_id = access_request_id
        self.access_token = safeguard.access_token
        return credential

    def do_check_in_credential(self):
        try:
            self.logger.debug("Checking in credential")
            if self.access_request_id is None:
                raise SafeguardException('Missing access_request_id')
            safeguard = self._make_safeguard_instance()
            safeguard.checkin_credential(self.access_request_id)
        except SafeguardException as exc:
            self.logger.error("Error checking in credential %s", exc)
            raise exc

    def _make_safeguard_instance(self):
        safeguard = self._safeguard_client_factory.new_instance(
            access_token=self.access_token,
            session_access_token=self.token,
            gateway_username=self.connection.gateway_username,
            gateway_password=self.connection.gateway_password
        )
        return safeguard

    @cookie_property
    def access_request_id(self):
        return None

    @cookie_property
    def access_token(self):
        return None

    @session_cookie_property
    def token(self):
        return None
